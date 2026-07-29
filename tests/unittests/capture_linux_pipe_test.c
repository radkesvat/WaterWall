// Stop-pipe lifecycle coverage for the Linux capture device.
//
// The stop pipe outlives every BringUp/BringDown cycle, so a wake token left in
// it by one bring-down would be consumed by the next bring-up's reader, which
// would exit immediately while the device still reported success. These tests
// pin the invariant that both lifecycle boundaries leave the pipe empty.
//
// capture_linux.c is compiled directly into this executable and the generic
// process runner is replaced with a linker wrap, so no iptables rule is ever
// installed, no sysctl is written, and root is not required. A synthetic reader
// routine replaces the NFQUEUE reader, so no netlink socket is opened either.

#include "devices/capture/capture.h"
#include "devices/capture/capture_linux_internal.h"
#include "global_state.h"
#include "worker.h"
#include "wproc.h"
#include "wthread.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

enum
{
    kTestCaptureRangeCount = 3,
    kTestQueueNumber       = 77,
    kJoinPollTimeoutMs     = 20,
    kWaitTimeoutMs         = 5000,
    kMaxCommandSteps       = 96,
    kMaxRecordedCommands   = 192,
    kMaxCommandText        = 64,
    kInjectedPacketId      = 0x10203040U,
    // Long enough for a freshly created reader to actually park inside poll().
    kReaderSettleUs = 50000
};

static const char *const test_cidrs[kTestCaptureRangeCount] = {
    "10.0.0.0/8",
    "192.168.0.0/16",
    "203.0.113.0/24",
};

// ---------------------------------------------------------------------------
// Command seam: nothing may reach a real iptables/sysctl binary.
// ---------------------------------------------------------------------------

typedef enum command_outcome_e
{
    kCommandSuccess = 0,
    kCommandFailure,
    kCommandTimeout,
    kCommandTimeoutApplied,
    kCommandSpawnFailure,
    kCommandOutputTooLarge,
    kCommandOutputTooLargeApplied
} command_outcome_t;

typedef struct command_step_s
{
    const char       *operation;
    const char       *cidr;
    command_outcome_t outcome;
} command_step_t;

typedef struct recorded_command_s
{
    char operation[kMaxCommandText];
    char cidr[kMaxCommandText];
} recorded_command_t;

static command_step_t     command_steps[kMaxCommandSteps];
static recorded_command_t recorded_commands[kMaxRecordedCommands];
static size_t             command_step_count       = 0;
static size_t             command_step_index       = 0;
static size_t             recorded_command_count   = 0;
static size_t             slow_delete_sleep_us     = 0;
static bool               fail_next_capture_thread = false;
static bool               fake_rule_present[kTestCaptureRangeCount];
static char               fake_rule_comments[kTestCaptureRangeCount][kMaxCommandText];
static capture_device_t  *expect_running_during_insert = NULL;
static capture_device_t  *expect_running_during_delete = NULL;
static capture_device_t  *observe_capture_thread       = NULL;
static pthread_t          observed_capture_thread;
static atomic_bool        observed_capture_thread_created;
static atomic_int         observed_capture_thread_joins;
static atomic_bool        inject_packet_on_next_insert;
static atomic_bool        injected_recv_pending;
static atomic_bool        injected_verdict_seen;
static atomic_int         injected_callback_count;
static int                injected_packet_peer_fd = -1;
static uint32_t           injected_verdict        = UINT32_MAX;

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);
int  __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg);
int  __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg);
int  __real_pthread_join(pthread_t thread, void **retval);
int  __wrap_pthread_join(pthread_t thread, void **retval);
ssize_t __real_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t __wrap_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t __real_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
                      socklen_t addrlen);
ssize_t __wrap_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
                      socklen_t addrlen);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void commandScriptReset(void)
{
    command_step_count           = 0;
    command_step_index           = 0;
    recorded_command_count       = 0;
    slow_delete_sleep_us         = 0;
    expect_running_during_insert = NULL;
    expect_running_during_delete = NULL;
    observe_capture_thread       = NULL;
    atomicStoreExplicit(&observed_capture_thread_created, false, memory_order_relaxed);
    atomicStoreExplicit(&observed_capture_thread_joins, 0, memory_order_relaxed);
    atomicStoreExplicit(&inject_packet_on_next_insert, false, memory_order_relaxed);
    atomicStoreExplicit(&injected_recv_pending, false, memory_order_relaxed);
    atomicStoreExplicit(&injected_verdict_seen, false, memory_order_relaxed);
    atomicStoreExplicit(&injected_callback_count, 0, memory_order_relaxed);
    injected_packet_peer_fd = -1;
    injected_verdict        = UINT32_MAX;
    memset(fake_rule_present, 0, sizeof(fake_rule_present));
    memset(fake_rule_comments, 0, sizeof(fake_rule_comments));
}

static void commandScriptAppend(const char *operation, const char *cidr, command_outcome_t outcome)
{
    require(command_step_count < kMaxCommandSteps, "too many scripted command steps");
    command_steps[command_step_count++] = (command_step_t) {.operation = operation, .cidr = cidr, .outcome = outcome};
}

static void requireCommandScriptConsumed(const char *message)
{
    require(command_step_index == command_step_count, message);
    require(recorded_command_count == command_step_count, "the recorded command count does not match the script");
}

static void requireCommandAt(size_t index, const char *operation, const char *cidr, const char *message)
{
    require(index < recorded_command_count, message);
    require(strcmp(recorded_commands[index].operation, operation) == 0, message);
    require(strcmp(recorded_commands[index].cidr, cidr) == 0, message);
}

static void scriptSuccessfulInsertions(void)
{
    for (uint32_t i = 0; i < kTestCaptureRangeCount; ++i)
    {
        commandScriptAppend("-I", test_cidrs[i], kCommandSuccess);
    }
}

static void scriptSuccessfulDeletions(void)
{
    for (uint32_t i = kTestCaptureRangeCount; i > 0; --i)
    {
        commandScriptAppend("-D", test_cidrs[i - 1], kCommandSuccess);
    }
}

static int commandRuleIndex(const char *cidr)
{
    for (uint32_t i = 0; i < kTestCaptureRangeCount; ++i)
    {
        if (strcmp(cidr, test_cidrs[i]) == 0)
        {
            return (int) i;
        }
    }
    return -1;
}

static void writeFakeInputRules(proc_command_result_t *out)
{
    char   snapshot[1024];
    size_t offset = 0;
    snapshot[0]   = '\0';

    for (uint32_t i = 0; i < kTestCaptureRangeCount; ++i)
    {
        if (! fake_rule_present[i])
        {
            continue;
        }

        int written = snprintf(snapshot + offset,
                               sizeof(snapshot) - offset,
                               "-A INPUT -s %s -m comment --comment %s -j NFQUEUE --queue-num %u --queue-bypass\n",
                               test_cidrs[i],
                               fake_rule_comments[i],
                               kTestQueueNumber);
        require(written > 0 && (size_t) written < sizeof(snapshot) - offset,
                "fake iptables snapshot exceeded its buffer");
        offset += (size_t) written;
    }

    out->output     = stringDuplicate(snapshot);
    out->output_len = offset;
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    require(file != NULL && argv != NULL && options != NULL && out != NULL,
            "Capture must pass a complete request to the process runner");
    require(strcmp(file, "iptables") == 0 || strcmp(file, "sysctl") == 0,
            "this test must never execute anything but the wrapped iptables/sysctl seams");

    // Rule deletion is deliberately slow in the lifecycle test so the reader can
    // observe running == false and exit before BringDown writes its wake token.
    if (slow_delete_sleep_us > 0 && strcmp(file, "iptables") == 0 && strcmp(argv[3], "-D") == 0)
    {
        usleep((useconds_t) slow_delete_sleep_us);
    }
    if (expect_running_during_delete != NULL && strcmp(file, "iptables") == 0 && strcmp(argv[3], "-D") == 0)
    {
        require(atomicLoadExplicit(&expect_running_during_delete->running, memory_order_relaxed),
                "BringDown stopped its reader before rule cleanup completed");
        require(! atomicLoadExplicit(&expect_running_during_delete->capture_active, memory_order_acquire),
                "BringDown left capture active while deleting NFQUEUE rules");
    }
    if (expect_running_during_insert != NULL && strcmp(file, "iptables") == 0 && strcmp(argv[3], "-I") == 0)
    {
        require(atomicLoadExplicit(&expect_running_during_insert->running, memory_order_relaxed),
                "BringUp exposed a rule before starting its reader");
        require(! atomicLoadExplicit(&expect_running_during_insert->capture_active, memory_order_acquire),
                "BringUp activated capture before every NFQUEUE rule was installed");
    }
    if (strcmp(file, "iptables") == 0 && strcmp(argv[3], "-I") == 0 &&
        atomicExchangeExplicit(&inject_packet_on_next_insert, false, memory_order_acq_rel))
    {
        require(injected_packet_peer_fd >= 0, "packet injection did not have a queue-socket peer");
        atomicStoreExplicit(&injected_recv_pending, true, memory_order_release);
        require(send(injected_packet_peer_fd, "p", 1, 0) == 1,
                "failed to wake the production reader for startup packet injection");

        bool verdict_seen = false;
        for (int waited_ms = 0; waited_ms < kWaitTimeoutMs && ! verdict_seen; waited_ms += 5)
        {
            verdict_seen = atomicLoadExplicit(&injected_verdict_seen, memory_order_acquire);
            if (! verdict_seen)
            {
                usleep(5000);
            }
        }
        require(verdict_seen, "the production reader did not issue a verdict for the startup packet");
        require(injected_verdict == NF_ACCEPT, "an NFQUEUE packet received during insertion was not accepted");
        require(atomicLoadExplicit(&injected_callback_count, memory_order_relaxed) == 0,
                "an inactive startup packet was dispatched to the capture callback");
    }

    memset(out, 0, sizeof(*out));
    if (strcmp(file, "sysctl") == 0)
    {
        out->exit_code = 0;
        return true;
    }

    require(recorded_command_count < kMaxRecordedCommands, "too many recorded iptables commands");
    const bool is_snapshot = strcmp(argv[3], "-S") == 0;
    require(options->max_output_bytes == (is_snapshot ? 1024U * 1024U : 64U * 1024U),
            "Capture used the wrong output cap for an iptables command");
    const char         *cidr   = is_snapshot ? "" : argv[6];
    recorded_command_t *record = &recorded_commands[recorded_command_count++];
    snprintf(record->operation, sizeof(record->operation), "%s", argv[3]);
    snprintf(record->cidr, sizeof(record->cidr), "%s", cidr);

    command_outcome_t outcome = kCommandSuccess;
    if (command_step_count != 0)
    {
        require(command_step_index < command_step_count, "Capture issued an unexpected iptables command");
        const command_step_t *step = &command_steps[command_step_index++];
        require(strcmp(argv[3], step->operation) == 0, "iptables operation did not match the lifecycle script");
        require(strcmp(cidr, step->cidr) == 0, "iptables CIDR did not match the lifecycle script");
        outcome = step->outcome;
    }

    int rule_index = is_snapshot ? -1 : commandRuleIndex(cidr);
    if (! is_snapshot)
    {
        require(rule_index >= 0, "iptables mutation referenced an unexpected CIDR");
    }

    const bool mutation_applied =
        outcome == kCommandSuccess || outcome == kCommandTimeoutApplied || outcome == kCommandOutputTooLargeApplied;
    if (mutation_applied && ! is_snapshot)
    {
        if (strcmp(argv[3], "-I") == 0)
        {
            fake_rule_present[rule_index] = true;
            snprintf(fake_rule_comments[rule_index], sizeof(fake_rule_comments[rule_index]), "%s", argv[10]);
        }
        else
        {
            require(strcmp(argv[3], "-D") == 0, "unexpected iptables mutation operation");
            fake_rule_present[rule_index] = false;
        }
    }

    switch (outcome)
    {
    case kCommandFailure:
        out->exit_code = 1;
        return false;
    case kCommandTimeout:
    case kCommandTimeoutApplied:
        out->timed_out = true;
        return false;
    case kCommandSpawnFailure:
        out->spawn_failed = true;
        return false;
    case kCommandOutputTooLarge:
    case kCommandOutputTooLargeApplied:
        out->output_too_large = true;
        return false;
    case kCommandSuccess:
    default:
        out->exit_code = 0;
        if (is_snapshot)
        {
            writeFakeInputRules(out);
        }
        return true;
    }
}

void __wrap_procCommandResultDrop(proc_command_result_t *out)
{
    __real_procCommandResultDrop(out);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg)
{
    if (fail_next_capture_thread)
    {
        fail_next_capture_thread = false;
        return EAGAIN;
    }

    const int result = __real_pthread_create(thread, attr, routine, arg);
    if (result == 0 && arg == observe_capture_thread)
    {
        observed_capture_thread = *thread;
        atomicStoreExplicit(&observed_capture_thread_created, true, memory_order_release);
    }
    return result;
}

int __wrap_pthread_join(pthread_t thread, void **retval)
{
    if (atomicLoadExplicit(&observed_capture_thread_created, memory_order_acquire) &&
        pthread_equal(thread, observed_capture_thread))
    {
        atomicAddExplicit(&observed_capture_thread_joins, 1, memory_order_relaxed);
    }
    return __real_pthread_join(thread, retval);
}

static size_t buildInjectedPacket(void *destination, size_t capacity)
{
    uint8_t      payload[20]      = {0x45};
    const size_t base_len         = (size_t) NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg)));
    const size_t packet_attr_len  = (size_t) NFA_ALIGN(NFA_LENGTH(sizeof(struct nfqnl_msg_packet_hdr)));
    const size_t payload_attr_len = (size_t) NFA_ALIGN(NFA_LENGTH(sizeof(payload)));
    const size_t message_len      = base_len + packet_attr_len + payload_attr_len;
    require(message_len <= capacity, "injected NFQUEUE packet exceeded the receive iovec");

    uint8_t *message = destination;
    memoryZero(message, message_len);

    struct nlmsghdr *nlh = (struct nlmsghdr *) message;
    nlh->nlmsg_len       = (uint32_t) message_len;
    nlh->nlmsg_type      = (uint16_t) ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET);

    struct nfgenmsg *gen = (struct nfgenmsg *) NLMSG_DATA(nlh);
    gen->version         = NFNETLINK_V0;

    struct nfattr *packet_attr                 = (struct nfattr *) (void *) (message + base_len);
    packet_attr->nfa_type                      = NFQA_PACKET_HDR;
    packet_attr->nfa_len                       = (uint16_t) NFA_LENGTH(sizeof(struct nfqnl_msg_packet_hdr));
    struct nfqnl_msg_packet_hdr *packet_header = NFA_DATA(packet_attr);
    packet_header->packet_id                   = htonl(kInjectedPacketId);
    packet_header->hw_protocol                 = htons(0x0800U);

    struct nfattr *payload_attr = (struct nfattr *) (void *) (message + base_len + packet_attr_len);
    payload_attr->nfa_type      = NFQA_PAYLOAD;
    payload_attr->nfa_len       = (uint16_t) NFA_LENGTH(sizeof(payload));
    memoryCopy(NFA_DATA(payload_attr), payload, sizeof(payload));
    return message_len;
}

ssize_t __wrap_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (atomicExchangeExplicit(&injected_recv_pending, false, memory_order_acq_rel))
    {
        char wake_byte;
        require(recv(sockfd, &wake_byte, 1, MSG_DONTWAIT) == 1,
                "failed to consume the startup packet's poll wake byte");
        require(msg != NULL && msg->msg_iov != NULL && msg->msg_iovlen >= 1,
                "production reader supplied an invalid recvmsg iovec");

        struct sockaddr_nl *source = msg->msg_name;
        require(source != NULL, "production reader did not request the netlink source address");
        memoryZero(source, sizeof(*source));
        source->nl_family = AF_NETLINK;
        source->nl_pid    = 0;
        msg->msg_namelen  = sizeof(*source);
        msg->msg_flags    = 0;

        return (ssize_t) buildInjectedPacket(msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
    }
    return __real_recvmsg(sockfd, msg, flags);
}

ssize_t __wrap_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
                      socklen_t addrlen)
{
    if (buf != NULL && len >= NLMSG_LENGTH(sizeof(struct nfgenmsg)))
    {
        const struct nlmsghdr *nlh = buf;
        if ((nlh->nlmsg_type & 0xFFU) == NFQNL_MSG_VERDICT)
        {
            const size_t attr_offset = (size_t) NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg)));
            require(len >= attr_offset + NFA_LENGTH(sizeof(struct nfqnl_msg_verdict_hdr)),
                    "production reader emitted a short NFQUEUE verdict");
            const struct nfattr *attr = (const struct nfattr *) (const void *) ((const uint8_t *) buf + attr_offset);
            require(NFA_TYPE(attr) == NFQA_VERDICT_HDR, "production reader emitted the wrong verdict attribute");
            const struct nfqnl_msg_verdict_hdr *verdict = NFA_DATA(attr);
            injected_verdict                            = ntohl(verdict->verdict);
            atomicStoreExplicit(&injected_verdict_seen, true, memory_order_release);
            return (ssize_t) len;
        }
    }
    return __real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

// ---------------------------------------------------------------------------
// Synthetic reader
// ---------------------------------------------------------------------------

typedef struct reader_probe_s
{
    atomic_int  started;
    atomic_int  exited;
    atomic_int  pipe_events;
    atomic_bool consume_token;
    atomic_bool exit_before_ready;
    atomic_bool exit_requested;
    atomic_bool verify_queue_fd_lifetime;
    atomic_bool queue_fd_changed_before_exit;
} reader_probe_t;

static WTHREAD_ROUTINE(probeReader) // NOLINT
{
    capture_device_t *cdev  = userdata;
    reader_probe_t   *probe = cdev->userdata;

    /*
     * Exercise the real per-reader pool ownership on every lifecycle
     * generation. A stop/restart test now fails in Debug unless BringDown
     * releases the joined reader's ownership before the replacement starts.
     */
    sbuf_t *pool_probe = bufferpoolGetSmallBuffer(cdev->reader_buffer_pool);
    bufferpoolReuseBuffer(cdev->reader_buffer_pool, pool_probe);

    atomicAddExplicit(&probe->started, 1, memory_order_relaxed);

    if (atomicLoadExplicit(&probe->exit_before_ready, memory_order_relaxed))
    {
        atomicAddExplicit(&probe->exited, 1, memory_order_relaxed);
        return 0;
    }

    int reader_socket = -1;
    if (! captureLinuxReaderPublishReady(cdev, &reader_socket))
    {
        atomicAddExplicit(&probe->exited, 1, memory_order_relaxed);
        return 0;
    }
    require(reader_socket >= 0, "the readiness handshake did not provide a valid queue socket");

    struct stat reader_socket_identity;
    if (atomicLoadExplicit(&probe->verify_queue_fd_lifetime, memory_order_relaxed))
    {
        require(fstat(reader_socket, &reader_socket_identity) == 0,
                "failed to record the reader-owned queue descriptor identity");
    }

    struct pollfd fds;
    fds.fd     = cdev->linux_pipe_fds[0];
    fds.events = POLLIN;

    while (atomicLoadExplicit(&cdev->running, memory_order_relaxed))
    {
        if (atomicLoadExplicit(&probe->exit_requested, memory_order_relaxed))
        {
            break;
        }
        fds.revents = 0;
        int ret     = poll(&fds, 1, kJoinPollTimeoutMs);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        if (ret > 0 && (fds.revents & POLLIN) != 0)
        {
            atomicAddExplicit(&probe->pipe_events, 1, memory_order_relaxed);
            if (atomicLoadExplicit(&probe->consume_token, memory_order_relaxed))
            {
                char    token = 0;
                ssize_t got   = read(cdev->linux_pipe_fds[0], &token, 1);
                discard got;
            }
            break;
        }
    }

    if (atomicLoadExplicit(&probe->verify_queue_fd_lifetime, memory_order_relaxed))
    {
        struct stat current_identity;
        if (fstat(reader_socket, &current_identity) != 0 || current_identity.st_dev != reader_socket_identity.st_dev ||
            current_identity.st_ino != reader_socket_identity.st_ino)
        {
            atomicStoreExplicit(&probe->queue_fd_changed_before_exit, true, memory_order_relaxed);
        }
    }

    atomicAddExplicit(&probe->exited, 1, memory_order_relaxed);
    return 0;
}

// ---------------------------------------------------------------------------
// Device scaffolding
// ---------------------------------------------------------------------------

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pool;
    buffer_pool_t *buffer_pools[1];
} test_env_t;

static void envSetup(test_env_t *env)
{
    env->large_master    = masterpoolCreateWithCapacity(16);
    env->small_master    = masterpoolCreateWithCapacity(16);
    env->buffer_pool     = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    env->buffer_pools[0] = env->buffer_pool;

    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.ram_profile           = 1;
    tl_wid                       = 0;
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools = NULL;
    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

// Build only the fields BringUp/BringDown touch. caputredeviceCreate() itself
// needs a real netlink socket, which this test deliberately avoids.
static void testDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    discard device;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void deviceSetup(capture_device_t *cdev, test_env_t *env, reader_probe_t *probe)
{
    memset(cdev, 0, sizeof(*cdev));
    memset(probe, 0, sizeof(*probe));

    cdev->name                = stringDuplicate("capture-pipe-test");
    cdev->socket              = -1;
    cdev->queue_number        = kTestQueueNumber;
    cdev->capture_range_count = kTestCaptureRangeCount;
    cdev->capture_cidrs       = memoryAllocateZero(kTestCaptureRangeCount * sizeof(char *));
    for (uint32_t i = 0; i < kTestCaptureRangeCount; ++i)
    {
        cdev->capture_cidrs[i] = stringDuplicate(test_cidrs[i]);
    }
    cdev->rule_states        = memoryAllocateZero(kTestCaptureRangeCount * sizeof(*cdev->rule_states));
    cdev->rule_token         = UINT64_C(0x1122334455667788);
    cdev->queue_restartable  = true;
    cdev->reader_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    cdev->routine_reader     = probeReader;
    cdev->userdata           = probe;
    cdev->running            = false;
    cdev->up                 = false;

    require(pipe(cdev->linux_pipe_fds) == 0, "test pipe creation failed");
    require(capturedeviceMakeStopPipeNonblocking(cdev->linux_pipe_fds[0]),
            "the production helper failed to make the stop pipe read end nonblocking");
    cdev->socket = dup(STDERR_FILENO);
    require(cdev->socket >= 0, "failed to create a harmless queue-socket stand-in");
    require(pthread_mutex_init(&cdev->reader_state_mutex, NULL) == 0, "failed to initialize the reader-state mutex");
    require(pthread_cond_init(&cdev->reader_state_changed, NULL) == 0,
            "failed to initialize the reader-state condition variable");
    cdev->reader_session = deviceReaderSessionCreate(16, 512, cdev, testDeliverPacket, cdev->reader_buffer_pool);
}

static void deviceTeardown(capture_device_t *cdev)
{
    deviceReaderSessionEnd(cdev->reader_session);
    deviceReaderSessionUnref(cdev->reader_session);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    if (cdev->socket >= 0)
    {
        close(cdev->socket);
        cdev->socket = -1;
    }
    close(cdev->linux_pipe_fds[0]);
    close(cdev->linux_pipe_fds[1]);
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        memoryFree(cdev->capture_cidrs[i]);
    }
    memoryFree(cdev->capture_cidrs);
    memoryFree(cdev->rule_states);
    memoryFree(cdev->name);
    pthread_cond_destroy(&cdev->reader_state_changed);
    pthread_mutex_destroy(&cdev->reader_state_mutex);
}

static capture_device_t *ownedDeviceCreate(test_env_t *env, reader_probe_t *probe)
{
    capture_device_t *cdev = memoryAllocate(sizeof(*cdev));
    deviceSetup(cdev, env, probe);
    return cdev;
}

static uint32_t countRuleState(const capture_device_t *cdev, capture_rule_state_t state)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < cdev->capture_range_count; ++i)
    {
        count += cdev->rule_states[i] == state ? 1U : 0U;
    }
    return count;
}

static void requireAllRulesInState(const capture_device_t *cdev, capture_rule_state_t state, const char *message)
{
    require(countRuleState(cdev, state) == cdev->capture_range_count, message);
}

static void attachQueueSocket(capture_device_t *cdev, int pair[2])
{
    require(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "failed to create a queue-socket test pair");
    close(cdev->socket);
    cdev->socket = pair[0];
}

static void requireQueueSocketClosed(const capture_device_t *cdev, int former_socket)
{
    require(! cdev->queue_restartable, "terminal lifecycle failure left the queue restartable");
    require(cdev->socket == -1, "terminal lifecycle failure retained its queue socket descriptor");
    errno = 0;
    require(fcntl(former_socket, F_GETFD) == -1 && errno == EBADF,
            "terminal lifecycle failure did not close the bound queue socket");
}

static bool pipeHasReadableData(const capture_device_t *cdev)
{
    struct pollfd fds = {.fd = cdev->linux_pipe_fds[0], .events = POLLIN, .revents = 0};
    int           ret = poll(&fds, 1, 0);
    require(ret >= 0, "poll on the stop pipe failed");
    return ret > 0 && (fds.revents & POLLIN) != 0;
}

static void waitForReaderExits(reader_probe_t *probe, int expected)
{
    for (int waited_ms = 0; waited_ms < kWaitTimeoutMs; waited_ms += 5)
    {
        if (atomicLoadExplicit(&probe->exited, memory_order_relaxed) >= expected)
        {
            return;
        }
        usleep(5000);
    }
    require(false, "a synthetic reader never exited");
}

static void injectedCaptureCallback(capture_device_t *cdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    discard cdev;
    discard userdata;
    atomicAddExplicit(&injected_callback_count, 1, memory_order_relaxed);
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

// ---------------------------------------------------------------------------
// Drain primitive
// ---------------------------------------------------------------------------

static void testDrainEmptiesThePipe(test_env_t *env)
{
    commandScriptReset();
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    for (int i = 0; i < 5; ++i)
    {
        require(write(cdev.linux_pipe_fds[1], "x", 1) == 1, "failed to write a stop token");
    }
    require(pipeHasReadableData(&cdev), "the test wrote tokens but the pipe reports no readable data");

    require(capturedeviceDrainStopPipe(&cdev), "draining a pipe holding several tokens must succeed");
    require(! pipeHasReadableData(&cdev), "the drain left readable data in the stop pipe");

    // Draining an already-empty pipe must return promptly and successfully; the
    // nonblocking read end is what makes that possible.
    require(capturedeviceDrainStopPipe(&cdev), "draining an already-empty pipe must succeed");
    require(! pipeHasReadableData(&cdev), "draining an empty pipe made it readable");

    deviceTeardown(&cdev);
}

static void testDrainReportsBrokenPipe(test_env_t *env)
{
    commandScriptReset();
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    // Closing the write end turns every subsequent read into EOF, which is a
    // lifecycle failure rather than "the pipe is empty".
    close(cdev.linux_pipe_fds[1]);
    require(! capturedeviceDrainStopPipe(&cdev), "a stop pipe whose write end is gone must report failure");

    close(cdev.socket);
    close(cdev.linux_pipe_fds[0]);
    deviceReaderSessionEnd(cdev.reader_session);
    deviceReaderSessionUnref(cdev.reader_session);
    bufferpoolDestroy(cdev.reader_buffer_pool);
    for (uint32_t i = 0; i < cdev.capture_range_count; ++i)
    {
        memoryFree(cdev.capture_cidrs[i]);
    }
    memoryFree(cdev.capture_cidrs);
    memoryFree(cdev.rule_states);
    memoryFree(cdev.name);
    pthread_cond_destroy(&cdev.reader_state_changed);
    pthread_mutex_destroy(&cdev.reader_state_mutex);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// A reader may observe the wake token without consuming it. BringDown owns the
// pipe after joining and must drain that stale token before the next cycle.
static void testStaleTokenDoesNotKillTheNextReader(test_env_t *env)
{
    commandScriptReset();
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    atomicStoreExplicit(&probe.consume_token, false, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "the first bring-up must succeed");
    require(cdev.up, "the first bring-up did not mark the device up");
    require(! cdev.reader_stop_requested, "bring-up inherited an old reader stop request");

    require(caputredeviceBringDown(&cdev), "the first bring-down must succeed");
    waitForReaderExits(&probe, 1);
    require(cdev.reader_stop_requested, "bring-down did not classify the reader exit as requested");

    // Whether the reader observed the token is a race, not an invariant: stop
    // clears `running` before writing the token, so a reader that has published
    // readiness but not yet re-checked `running` leaves without polling. Either
    // way the token went unconsumed, which is the case this test is about.
    const int events_after_first = atomicLoadExplicit(&probe.pipe_events, memory_order_relaxed);
    require(events_after_first <= 1, "the first reader observed more stop events than were written");
    require(! pipeHasReadableData(&cdev), "bring-down left an unread wake token in the stop pipe");

    // Same device object, second cycle: this reader must stay alive.
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "the second bring-up on the same device must succeed");
    require(! cdev.reader_stop_requested, "restart did not clear the prior reader stop request");

    // Well past several poll intervals: a stale token would have ended it here.
    usleep(120000);
    require(atomicLoadExplicit(&probe.pipe_events, memory_order_relaxed) == events_after_first,
            "the second reader saw a stale stop-pipe event");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "the second reader exited before the test brought the device down");

    require(caputredeviceBringDown(&cdev), "the second bring-down must succeed");
    waitForReaderExits(&probe, 2);
    require(atomicLoadExplicit(&probe.pipe_events, memory_order_relaxed) <= events_after_first + 1,
            "the second reader observed more stop events than were written");
    require(! pipeHasReadableData(&cdev), "the second bring-down left a token in the stop pipe");
    require(! cdev.up, "the device is still marked up after bring-down");

    deviceTeardown(&cdev);
}

// A reader that consumes the token leaves nothing behind either, and the pipe
// stays empty across repeated cycles.
static void testRepeatedCyclesKeepThePipeEmpty(test_env_t *env)
{
    commandScriptReset();
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    for (int cycle = 0; cycle < 3; ++cycle)
    {
        require(caputredeviceBringUp(&cdev), "a repeated bring-up must succeed");
        require(caputredeviceBringDown(&cdev), "a repeated bring-down must succeed");
        require(! pipeHasReadableData(&cdev), "a bring-up/bring-down cycle left a token in the stop pipe");
    }
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 3, "every cycle must start a reader");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 3, "every reader must be joined");

    deviceTeardown(&cdev);
}

static void testDrainFailurePreventsStartup(test_env_t *env)
{
    commandScriptReset();
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    // A bring-up whose defensive drain fails must refuse before it installs any
    // rule or starts a reader.
    const size_t commands_before = recorded_command_count;
    close(cdev.linux_pipe_fds[1]);
    require(! caputredeviceBringUp(&cdev), "bring-up must fail when the stop pipe cannot be drained");
    require(recorded_command_count == commands_before, "a failed bring-up must not install any rule");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 0, "a failed bring-up must not start a reader");
    require(! cdev.up, "a failed bring-up marked the device up");
    close(cdev.socket);
    close(cdev.linux_pipe_fds[0]);

    for (uint32_t i = 0; i < cdev.capture_range_count; ++i)
    {
        memoryFree(cdev.capture_cidrs[i]);
    }
    memoryFree(cdev.capture_cidrs);
    memoryFree(cdev.rule_states);
    memoryFree(cdev.name);
    pthread_cond_destroy(&cdev.reader_state_changed);
    pthread_mutex_destroy(&cdev.reader_state_mutex);
}

static void testReaderExitBeforeReadinessPreventsInsertion(test_env_t *env)
{
    commandScriptReset();

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    const int queue_socket = cdev.socket;
    atomicStoreExplicit(&probe.exit_before_ready, true, memory_order_relaxed);

    require(! caputredeviceBringUp(&cdev), "a reader that exits before readiness must fail bring-up");
    require(recorded_command_count == 0, "pre-readiness reader failure installed an NFQUEUE rule");
    requireAllRulesInState(&cdev, kCaptureRuleAbsent, "pre-readiness reader failure changed firewall state");
    require(! atomicLoadExplicit(&cdev.up, memory_order_acquire) &&
                ! atomicLoadExplicit(&cdev.capture_active, memory_order_acquire) &&
                ! atomicLoadExplicit(&cdev.running, memory_order_acquire),
            "pre-readiness reader failure left capture operational");
    require(! cdev.reader_thread_joinable, "pre-readiness reader failure left its thread unjoined");
    require(cdev.reader_failed, "pre-readiness reader failure was not recorded");
    requireQueueSocketClosed(&cdev, queue_socket);
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 1 &&
                atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "pre-readiness reader failure did not run and join exactly one reader");

    deviceTeardown(&cdev);
}

static void testPacketDuringInsertionIsAcceptedWithoutDispatch(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    scriptSuccessfulDeletions();

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    int queue_pair[2];
    attachQueueSocket(&cdev, queue_pair);
    cdev.routine_reader      = captureLinuxReadRoutine;
    cdev.read_event_callback = injectedCaptureCallback;

    expect_running_during_insert = &cdev;
    injected_packet_peer_fd      = queue_pair[1];
    atomicStoreExplicit(&inject_packet_on_next_insert, true, memory_order_release);
    require(caputredeviceBringUp(&cdev), "bring-up failed around startup packet injection");
    expect_running_during_insert = NULL;
    require(atomicLoadExplicit(&injected_verdict_seen, memory_order_acquire),
            "startup packet injection did not observe a verdict");
    require(injected_verdict == NF_ACCEPT, "startup packet injection did not receive NF_ACCEPT");
    require(atomicLoadExplicit(&injected_callback_count, memory_order_relaxed) == 0,
            "startup packet injection reached the capture callback");
    require(atomicLoadExplicit(&cdev.capture_active, memory_order_acquire),
            "capture did not activate after all rules were installed");

    require(caputredeviceBringDown(&cdev), "bring-down after startup packet injection failed");
    close(queue_pair[1]);
    requireCommandScriptConsumed("startup packet injection changed the firewall lifecycle command sequence");
    deviceTeardown(&cdev);
}

// Regression: removing the last iptables rule stops new packets from being
// enqueued, but anything the kernel queued just before that is still awaiting a
// verdict. The reader cannot be relied on to have taken it -- its drain is
// bounded per wakeup and the stop pipe is handled before the queue socket -- and
// on the successful-cleanup path the queue socket is left open, so those packets
// used to sit unverdicted until the device was destroyed or brought back up.
//
// probeReader never reads the queue socket, so the injected packet is guaranteed
// to still be pending when the reader is stopped. BringDown must return only
// after it has been accepted back to the host stack.
static void testPendingQueuePacketIsAcceptedDuringBringDown(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    scriptSuccessfulDeletions();

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    int queue_pair[2];
    attachQueueSocket(&cdev, queue_pair);
    cdev.read_event_callback = injectedCaptureCallback;

    require(caputredeviceBringUp(&cdev), "bring-up before the pending-packet drain failed");

    // Queue a packet the reader will never consume. The wake byte is what
    // __wrap_recvmsg consumes when it hands the injected packet over.
    injected_packet_peer_fd = queue_pair[1];
    atomicStoreExplicit(&injected_recv_pending, true, memory_order_release);
    require(send(queue_pair[1], "p", 1, 0) == 1, "failed to queue the pending NFQUEUE packet");

    require(caputredeviceBringDown(&cdev), "bring-down with a pending queue packet failed");

    require(atomicLoadExplicit(&injected_verdict_seen, memory_order_acquire),
            "a packet still queued at reader stop was left without a verdict");
    require(injected_verdict == NF_ACCEPT, "a packet stranded by bring-down was not accepted back to the host stack");
    require(atomicLoadExplicit(&injected_callback_count, memory_order_relaxed) == 0,
            "a residual packet drained during bring-down was dispatched to the capture callback");

    close(queue_pair[1]);
    requireCommandScriptConsumed("the pending-packet drain changed the firewall lifecycle command sequence");
    deviceTeardown(&cdev);
}

static void testPartialInsertionRollsBackConfirmedPrefix(test_env_t *env)
{
    commandScriptReset();
    commandScriptAppend("-I", test_cidrs[0], kCommandSuccess);
    commandScriptAppend("-I", test_cidrs[1], kCommandFailure);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    expect_running_during_insert = &cdev;
    require(! caputredeviceBringUp(&cdev), "a partial rule insertion failure must fail bring-up");
    expect_running_during_insert = NULL;
    require(! cdev.up, "partial insertion failure marked the device up");
    require(! cdev.running, "partial insertion failure left the reader running");
    requireAllRulesInState(&cdev, kCaptureRuleAbsent, "successful rollback did not clear every rule state");
    require(cdev.queue_restartable, "a fully rolled-back insertion failure unnecessarily disabled the queue");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 1,
            "partial insertion did not start its reader before exposing the first rule");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "partial insertion rollback did not stop and join its reader");
    requireCommandScriptConsumed("partial insertion rollback did not issue the expected command sequence");
    requireCommandAt(2, "-D", test_cidrs[0], "partial insertion rollback did not remove the confirmed prefix");

    deviceTeardown(&cdev);
}

static void testPartialRollbackFailureIsRetriedByDestroy(test_env_t *env)
{
    commandScriptReset();
    commandScriptAppend("-I", test_cidrs[0], kCommandSuccess);
    commandScriptAppend("-I", test_cidrs[1], kCommandFailure);
    commandScriptAppend("-D", test_cidrs[0], kCommandFailure);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    int               queue_pair[2];
    attachQueueSocket(cdev, queue_pair);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    atomicStoreExplicit(&probe.verify_queue_fd_lifetime, true, memory_order_relaxed);

    require(! caputredeviceBringUp(cdev), "a failed insertion with failed rollback must fail bring-up");
    require(countRuleState(cdev, kCaptureRuleInstalled) == 1,
            "failed rollback did not retain the confirmed installed rule");
    require(! cdev->up && ! cdev->running, "failed startup rollback left the device operational");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 1,
            "failed startup rollback did not start its reader before insertion");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "failed startup rollback did not stop and join its reader");
    require(! atomicLoadExplicit(&probe.queue_fd_changed_before_exit, memory_order_relaxed),
            "startup rollback closed the queue descriptor while its reader still owned it");
    requireQueueSocketClosed(cdev, queue_pair[0]);

    capturedeviceDestroy(cdev);
    close(queue_pair[1]);
    requireCommandScriptConsumed("destruction did not retry the pending startup rollback");
    requireCommandAt(3, "-D", test_cidrs[0], "destruction retried the wrong pending rule");
}

static void testReverseDeletionPreservesPerRuleState(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    commandScriptAppend("-D", test_cidrs[2], kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[1], kCommandFailure);
    commandScriptAppend("-D", test_cidrs[1], kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    int               queue_pair[2];
    attachQueueSocket(cdev, queue_pair);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    atomicStoreExplicit(&probe.verify_queue_fd_lifetime, true, memory_order_relaxed);

    require(caputredeviceBringUp(cdev), "initial bring-up for reverse deletion failed");
    require(! caputredeviceBringDown(cdev), "a scripted middle deletion failure must fail bring-down");
    require(cdev->rule_states[0] == kCaptureRuleInstalled && cdev->rule_states[1] == kCaptureRuleInstalled &&
                cdev->rule_states[2] == kCaptureRuleAbsent,
            "reverse cleanup did not preserve exact per-rule state after a middle failure");
    require(! cdev->up && ! cdev->running, "failed bring-down left the device operational");
    require(! cdev->queue_restartable, "failed rule cleanup left the queue restartable");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1, "failed bring-down did not join its reader");
    require(! atomicLoadExplicit(&probe.queue_fd_changed_before_exit, memory_order_relaxed),
            "reverse cleanup closed the queue descriptor while its reader still owned it");
    requireQueueSocketClosed(cdev, queue_pair[0]);
    requireCommandAt(3, "-D", test_cidrs[2], "cleanup did not begin at the end of the installed prefix");
    requireCommandAt(4, "-D", test_cidrs[1], "cleanup did not stop at the scripted middle failure");

    capturedeviceDestroy(cdev);
    close(queue_pair[1]);
    requireCommandScriptConsumed("destruction did not finish reverse cleanup using exact per-rule state");
}

static void testRebringupRefusesWhenPendingCleanupStillFails(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    commandScriptAppend("-D", test_cidrs[2], kCommandFailure);
    commandScriptAppend("-D", test_cidrs[2], kCommandFailure);
    scriptSuccessfulDeletions();

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    int               queue_pair[2];
    attachQueueSocket(cdev, queue_pair);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    atomicStoreExplicit(&probe.verify_queue_fd_lifetime, true, memory_order_relaxed);

    require(caputredeviceBringUp(cdev), "initial bring-up for pending-cleanup refusal failed");
    require(! caputredeviceBringDown(cdev), "the scripted deletion failure must fail bring-down");
    requireAllRulesInState(cdev, kCaptureRuleInstalled, "the failed first deletion must retain every installed rule");
    require(! atomicLoadExplicit(&probe.queue_fd_changed_before_exit, memory_order_relaxed),
            "pending-cleanup bring-down closed the queue descriptor while its reader still owned it");
    requireQueueSocketClosed(cdev, queue_pair[0]);
    require(! caputredeviceBringUp(cdev), "re-bring-up must fail while pending cleanup still fails");
    requireAllRulesInState(cdev, kCaptureRuleInstalled, "failed re-bring-up cleanup changed retained rule state");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 1,
            "failed re-bring-up started a second reader");
    require(recorded_command_count == 5, "failed pending cleanup must not issue any fresh insertion");

    capturedeviceDestroy(cdev);
    close(queue_pair[1]);
    requireCommandScriptConsumed("destruction did not clear the prefix left by failed re-bring-up cleanup");
}

static void testBringdownFailureIsRetriedByDestroy(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    commandScriptAppend("-D", test_cidrs[2], kCommandFailure);
    scriptSuccessfulDeletions();

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    int               queue_pair[2];
    attachQueueSocket(cdev, queue_pair);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    atomicStoreExplicit(&probe.verify_queue_fd_lifetime, true, memory_order_relaxed);

    require(caputredeviceBringUp(cdev), "bring-up before destruction retry failed");
    expect_running_during_delete = cdev;
    require(! caputredeviceBringDown(cdev), "a rule deletion failure must fail bring-down");
    expect_running_during_delete = NULL;
    require(! cdev->up && ! cdev->running, "failed bring-down did not stop the device");
    requireAllRulesInState(cdev, kCaptureRuleInstalled, "failed first deletion did not retain every installed rule");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1, "failed bring-down did not join the reader");
    require(! atomicLoadExplicit(&probe.queue_fd_changed_before_exit, memory_order_relaxed),
            "failed bring-down closed the queue descriptor while its reader still owned it");
    requireQueueSocketClosed(cdev, queue_pair[0]);

    capturedeviceDestroy(cdev);
    close(queue_pair[1]);
    requireCommandScriptConsumed("destruction did not retry a failed bring-down exactly once");
}

static void testReaderCreationFailureDoesNotTouchFirewall(test_env_t *env)
{
    commandScriptReset();

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    fail_next_capture_thread = true;
    require(! caputredeviceBringUp(&cdev), "reader creation failure must fail bring-up");
    require(! fail_next_capture_thread, "the injected pthread_create failure was not consumed");
    require(! cdev.up && ! cdev.running, "reader creation failure left the device operational");
    requireAllRulesInState(&cdev, kCaptureRuleAbsent, "reader creation failure changed firewall rule state");
    require(cdev.queue_restartable, "reader creation failure disabled a queue that has no installed rules");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 0,
            "the failed pthread_create unexpectedly ran the reader");
    require(recorded_command_count == 0, "reader creation failure issued an iptables command");

    deviceTeardown(&cdev);
}

static void testReaderDeathFailsOpenAndDestroyJoins(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    scriptSuccessfulDeletions();

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    int               queue_pair[2];
    attachQueueSocket(cdev, queue_pair);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    observe_capture_thread = cdev;

    require(caputredeviceBringUp(cdev), "bring-up before injected reader death failed");
    require(atomicLoadExplicit(&cdev->capture_active, memory_order_acquire),
            "successful bring-up did not activate capture");
    require(cdev->reader_ready && cdev->reader_thread_joinable,
            "successful bring-up did not retain a ready, joinable reader");

    atomicStoreExplicit(&probe.exit_requested, true, memory_order_release);
    for (int waited_ms = 0; waited_ms < kWaitTimeoutMs; waited_ms += 5)
    {
        pthread_mutex_lock(&cdev->reader_state_mutex);
        const bool failed = cdev->reader_failed;
        pthread_mutex_unlock(&cdev->reader_state_mutex);
        if (failed)
        {
            break;
        }
        usleep(5000);
    }

    pthread_mutex_lock(&cdev->reader_state_mutex);
    const bool reader_failed   = cdev->reader_failed;
    const bool reader_ready    = cdev->reader_ready;
    const bool reader_joinable = cdev->reader_thread_joinable;
    pthread_mutex_unlock(&cdev->reader_state_mutex);
    require(reader_failed && ! reader_ready, "unexpected reader exit did not publish failed/not-ready state");
    require(! cdev->reader_stop_requested, "unexpected reader exit was misclassified as a requested stop");
    require(reader_joinable, "an exited reader stopped being joinable before lifecycle teardown");
    require(! atomicLoadExplicit(&cdev->running, memory_order_acquire) &&
                ! atomicLoadExplicit(&cdev->up, memory_order_acquire) &&
                ! atomicLoadExplicit(&cdev->capture_active, memory_order_acquire),
            "unexpected reader exit left capture operational");
    requireAllRulesInState(cdev, kCaptureRuleInstalled, "unexpected reader exit changed installed-rule accounting");
    requireQueueSocketClosed(cdev, queue_pair[0]);
    require(atomicLoadExplicit(&observed_capture_thread_joins, memory_order_relaxed) == 0,
            "the reader was joined before destruction took lifecycle ownership");

    capturedeviceDestroy(cdev);
    close(queue_pair[1]);
    require(atomicLoadExplicit(&observed_capture_thread_joins, memory_order_relaxed) == 1,
            "destruction did not join the successfully created reader exactly once");
    requireCommandScriptConsumed("destruction did not retry cleanup after unexpected reader death");
}

static void testInsertionTimeoutStopsAndRollsBackConfirmedRules(test_env_t *env)
{
    commandScriptReset();
    commandScriptAppend("-I", test_cidrs[0], kCommandSuccess);
    commandScriptAppend("-I", test_cidrs[1], kCommandTimeout);
    commandScriptAppend("-S", "", kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    int queue_pair[2];
    attachQueueSocket(&cdev, queue_pair);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    expect_running_during_insert = &cdev;
    require(! caputredeviceBringUp(&cdev), "a timed-out insertion must fail bring-up");
    expect_running_during_insert = NULL;
    requireAllRulesInState(&cdev, kCaptureRuleAbsent, "insertion timeout rollback left a pending or unknown rule");
    require(! cdev.up && ! cdev.running, "insertion timeout left the device operational");
    require(cdev.queue_restartable && cdev.socket == queue_pair[0],
            "a fully reconciled insertion timeout unnecessarily disabled the queue");
    require(fcntl(queue_pair[0], F_GETFD) != -1, "a fully reconciled insertion timeout closed the queue socket");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 1,
            "insertion timeout did not start its reader before insertion");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "insertion timeout rollback did not stop and join its reader");
    requireCommandScriptConsumed("insertion timeout attempted a later insertion or skipped rollback");

    close(queue_pair[0]);
    close(queue_pair[1]);
    cdev.socket = -1;
    deviceTeardown(&cdev);
}

static void testCommittedInsertionTimeoutIsReconciledAndRemoved(test_env_t *env)
{
    commandScriptReset();
    commandScriptAppend("-I", test_cidrs[0], kCommandSuccess);
    commandScriptAppend("-I", test_cidrs[1], kCommandTimeoutApplied);
    commandScriptAppend("-S", "", kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[1], kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    require(! caputredeviceBringUp(&cdev), "a committed-before-timeout insertion must fail bring-up");
    requireAllRulesInState(
        &cdev, kCaptureRuleAbsent, "committed-before-timeout insertion was not reconciled and deleted");
    require(! fake_rule_present[1], "the fake firewall retained the timed-out committed insertion");
    requireCommandAt(2, "-S", "", "timed-out insertion was not reconciled through an INPUT snapshot");
    requireCommandAt(3, "-D", test_cidrs[1], "reconciled timed-out insertion was not deleted first");
    requireCommandScriptConsumed("committed insertion timeout issued an unexpected cleanup sequence");
    require(cdev.queue_restartable, "a reconciled committed insertion timeout unnecessarily disabled the queue");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 1 &&
                atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "committed insertion timeout did not run and join its reader around insertion and rollback");

    deviceTeardown(&cdev);
}

static void testCommittedInsertionOutputLimitIsReconciledAndRemoved(test_env_t *env)
{
    commandScriptReset();
    commandScriptAppend("-I", test_cidrs[0], kCommandSuccess);
    commandScriptAppend("-I", test_cidrs[1], kCommandOutputTooLargeApplied);
    commandScriptAppend("-S", "", kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[1], kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    require(! caputredeviceBringUp(&cdev), "a committed-before-output-limit insertion must fail bring-up");
    requireAllRulesInState(
        &cdev, kCaptureRuleAbsent, "committed-before-output-limit insertion was not reconciled and deleted");
    require(! fake_rule_present[1], "the fake firewall retained the output-limited committed insertion");
    requireCommandAt(2, "-S", "", "output-limited insertion was not reconciled through an INPUT snapshot");
    requireCommandAt(3, "-D", test_cidrs[1], "reconciled output-limited insertion was not deleted first");
    requireCommandScriptConsumed("committed output-limit insertion issued an unexpected cleanup sequence");
    require(cdev.queue_restartable, "a reconciled output-limited insertion unnecessarily disabled the queue");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 1 &&
                atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "output-limited insertion did not run and join its reader around insertion and rollback");

    deviceTeardown(&cdev);
}

static void testDeletionTimeoutIsReconciledDuringDestroy(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    commandScriptAppend("-D", test_cidrs[2], kCommandTimeout);
    commandScriptAppend("-S", "", kCommandSuccess);
    scriptSuccessfulDeletions();

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    require(caputredeviceBringUp(cdev), "bring-up before deletion timeout failed");
    require(! caputredeviceBringDown(cdev), "a deletion timeout must fail bring-down");
    require(cdev->rule_states[2] == kCaptureRuleOutcomeUnknown,
            "timed-out deletion was not represented as outcome-unknown");
    require(recorded_command_count == 4, "deletion timeout did not stop its cleanup pass immediately");

    capturedeviceDestroy(cdev);
    requireCommandScriptConsumed("destruction did not reconcile and remove a timed-out deletion");
}

static void testCommittedDeletionTimeoutDoesNotBlockEarlierCleanup(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    commandScriptAppend("-D", test_cidrs[2], kCommandTimeoutApplied);
    commandScriptAppend("-S", "", kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[1], kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    require(caputredeviceBringUp(cdev), "bring-up before committed deletion timeout failed");
    require(! caputredeviceBringDown(cdev), "a committed-before-timeout deletion must fail bring-down");
    require(cdev->rule_states[2] == kCaptureRuleOutcomeUnknown,
            "committed-before-timeout deletion was not represented as outcome-unknown");
    require(! fake_rule_present[2], "the fake firewall did not apply the timed-out deletion");

    capturedeviceDestroy(cdev);
    requireCommandAt(4, "-S", "", "destruction did not reconcile the timed-out deletion");
    requireCommandAt(
        5, "-D", test_cidrs[1], "an already-applied timed-out deletion blocked cleanup of an earlier rule");
    requireCommandScriptConsumed("committed deletion timeout issued an unexpected cleanup sequence");
}

static void testCommittedDeletionOutputLimitDoesNotBlockEarlierCleanup(test_env_t *env)
{
    commandScriptReset();
    scriptSuccessfulInsertions();
    commandScriptAppend("-D", test_cidrs[2], kCommandOutputTooLargeApplied);
    commandScriptAppend("-S", "", kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[1], kCommandSuccess);
    commandScriptAppend("-D", test_cidrs[0], kCommandSuccess);

    reader_probe_t    probe;
    capture_device_t *cdev = ownedDeviceCreate(env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    require(caputredeviceBringUp(cdev), "bring-up before committed output-limited deletion failed");
    require(! caputredeviceBringDown(cdev), "a committed-before-output-limit deletion must fail bring-down");
    require(cdev->rule_states[2] == kCaptureRuleOutcomeUnknown,
            "committed-before-output-limit deletion was not represented as outcome-unknown");
    require(! fake_rule_present[2], "the fake firewall did not apply the output-limited deletion");

    capturedeviceDestroy(cdev);
    requireCommandAt(4, "-S", "", "destruction did not reconcile the output-limited deletion");
    requireCommandAt(
        5, "-D", test_cidrs[1], "an already-applied output-limited deletion blocked cleanup of an earlier rule");
    requireCommandScriptConsumed("committed output-limited deletion issued an unexpected cleanup sequence");
}

// ---------------------------------------------------------------------------
// Bounded reader poll
// ---------------------------------------------------------------------------

static atomic_int production_reader_returned;

static WTHREAD_ROUTINE(productionReaderWrapper) // NOLINT
{
    discard captureLinuxReadRoutine(userdata);
    atomicStoreExplicit(&production_reader_returned, 1, memory_order_release);
    return 0;
}

// The production reader must be able to leave poll() on `running == false`
// alone. Without that, a bring-down whose wake write fails would join a thread
// parked in poll() forever. This runs the real routine, never delivers a token,
// and fails on a deadline rather than hanging the suite.
static void testProductionReaderLeavesPollWithoutWakeToken(test_env_t *env)
{
    commandScriptReset();
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    // A socketpair stands in for the netfilter socket: pollable, and permanently
    // silent, so neither descriptor the reader watches ever becomes readable.
    int pair[2];
    require(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair for the silent capture socket failed");
    cdev.socket = pair[0];

    atomicStoreExplicit(&production_reader_returned, 0, memory_order_relaxed);
    cdev.running = true;
    atomicThreadFence(memory_order_release);

    wthread_t thread;
    require(threadCreate(&thread, productionReaderWrapper, &cdev) == kWThreadErrorNone,
            "failed to start the production reader");

    // Let it settle inside poll(), then withdraw the only other exit condition.
    // Without the settle it could leave through the top-of-loop `running` check
    // and prove nothing about poll() itself.
    usleep(kReaderSettleUs);
    cdev.running = false;
    atomicThreadFence(memory_order_release);

    bool returned = false;
    for (int waited_ms = 0; waited_ms < kWaitTimeoutMs && ! returned; waited_ms += 5)
    {
        returned = atomicLoadExplicit(&production_reader_returned, memory_order_acquire) != 0;
        if (! returned)
        {
            usleep(5000);
        }
    }
    require(returned, "the production reader never left poll() without a wake token; its poll must stay bounded");
    require(safeThreadJoin(thread), "failed to join the production reader");
    require(! pipeHasReadableData(&cdev), "no wake token was written, so the stop pipe must still be empty");

    close(pair[0]);
    close(pair[1]);
    cdev.socket = -1;
    deviceTeardown(&cdev);
}

typedef struct bringdown_task_s
{
    capture_device_t *cdev;
    atomic_int        finished;
    atomic_int        result;
} bringdown_task_t;

static WTHREAD_ROUTINE(bringDownWorker) // NOLINT
{
    bringdown_task_t *task = userdata;
    const bool        ok   = caputredeviceBringDown(task->cdev);
    atomicStoreExplicit(&task->result, ok ? 1 : 0, memory_order_relaxed);
    atomicStoreExplicit(&task->finished, 1, memory_order_release);
    return 0;
}

// End-to-end version of the same hazard: a hard wake-write failure must be
// returned by bring-down instead of deadlocking its join. The production reader
// is used, so the bounded poll is the only thing that can release the join.
// Bring-down runs on its own thread and is awaited with a deadline, so a
// regression fails cleanly here instead of hanging the suite.
static void testWakeWriteFailureIsReportedNotDeadlocked(test_env_t *env)
{
    commandScriptReset();
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    int pair[2];
    require(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair for the silent capture socket failed");
    cdev.socket         = pair[0];
    cdev.routine_reader = productionReaderWrapper;

    atomicStoreExplicit(&production_reader_returned, 0, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "bring-up with the production reader must succeed");

    // The reader must genuinely be parked inside poll() before the wake write is
    // sabotaged; otherwise it would exit through the top-of-loop `running` check
    // and the join would never have been at risk.
    usleep(kReaderSettleUs);

    // Make the wake write fail hard (EBADF). The real write end stays open so the
    // post-join drain still runs against a valid descriptor.
    const int real_write_fd = cdev.linux_pipe_fds[1];
    cdev.linux_pipe_fds[1]  = -1;

    bringdown_task_t task = {.cdev = &cdev};
    wthread_t        down_thread;
    require(threadCreate(&down_thread, bringDownWorker, &task) == kWThreadErrorNone,
            "failed to start the bring-down worker");

    bool finished = false;
    for (int waited_ms = 0; waited_ms < kWaitTimeoutMs && ! finished; waited_ms += 5)
    {
        finished = atomicLoadExplicit(&task.finished, memory_order_acquire) != 0;
        if (! finished)
        {
            usleep(5000);
        }
    }
    require(finished, "bring-down deadlocked joining a reader that never received a wake token");
    require(safeThreadJoin(down_thread), "failed to join the bring-down worker");

    cdev.linux_pipe_fds[1] = real_write_fd;

    require(atomicLoadExplicit(&task.result, memory_order_relaxed) == 0,
            "a hard wake-write failure must be reported by bring-down");
    require(atomicLoadExplicit(&production_reader_returned, memory_order_acquire) != 0,
            "bring-down returned without the reader having exited");
    require(! cdev.up, "a failed bring-down must still mark the device down");
    require(! pipeHasReadableData(&cdev), "a failed wake write must not leave data in the stop pipe");

    // The device must still be reusable afterwards.
    cdev.routine_reader = probeReader;
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "bring-up after a failed wake write must succeed");
    require(caputredeviceBringDown(&cdev), "bring-down after a recovered wake path must succeed");
    require(! pipeHasReadableData(&cdev), "the recovery cycle left a token in the stop pipe");

    close(pair[0]);
    close(pair[1]);
    cdev.socket = -1;
    deviceTeardown(&cdev);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);

    testDrainEmptiesThePipe(&env);
    testDrainReportsBrokenPipe(&env);
    testStaleTokenDoesNotKillTheNextReader(&env);
    testRepeatedCyclesKeepThePipeEmpty(&env);
    testDrainFailurePreventsStartup(&env);
    testReaderExitBeforeReadinessPreventsInsertion(&env);
    testPacketDuringInsertionIsAcceptedWithoutDispatch(&env);
    testPendingQueuePacketIsAcceptedDuringBringDown(&env);
    testPartialInsertionRollsBackConfirmedPrefix(&env);
    testPartialRollbackFailureIsRetriedByDestroy(&env);
    testReverseDeletionPreservesPerRuleState(&env);
    testRebringupRefusesWhenPendingCleanupStillFails(&env);
    testBringdownFailureIsRetriedByDestroy(&env);
    testReaderCreationFailureDoesNotTouchFirewall(&env);
    testReaderDeathFailsOpenAndDestroyJoins(&env);
    testInsertionTimeoutStopsAndRollsBackConfirmedRules(&env);
    testCommittedInsertionTimeoutIsReconciledAndRemoved(&env);
    testCommittedInsertionOutputLimitIsReconciledAndRemoved(&env);
    testDeletionTimeoutIsReconciledDuringDestroy(&env);
    testCommittedDeletionTimeoutDoesNotBlockEarlierCleanup(&env);
    testCommittedDeletionOutputLimitDoesNotBlockEarlierCleanup(&env);
    // Isolated proof that the reader's poll is bounded, ordered before the
    // end-to-end case so a regression is attributed to the primitive first.
    testProductionReaderLeavesPollWithoutWakeToken(&env);
    testWakeWriteFailureIsReportedNotDeadlocked(&env);

    envTeardown(&env);

    printf("capture_linux_pipe_test: all tests passed\n");
    return 0;
}
