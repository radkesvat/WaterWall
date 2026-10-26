/*
 * Covers: Capture FIFO cancellation after device destruction and actual queue
 * setup, firewall rollback, single-worker fallback and restart ownership.
 * Setup: Public Capture lifecycle and real reader sessions; inert queue sockets,
 * synthetic configuration ACKs, recorded firewall mutations and held messages.
 * Cases: foreign FIFO cancellation; multiqueue success; explicit single queue;
 * extra/first queue bind refusal; steering fallback; stale restart activation.
 * Limits: Kernel NFQUEUE/firewall behavior belongs to namespace integration.
 * CTest: waterwall.capture_linux_message_lifetime_unit
 */
#include "devices/capture/capture_linux_private.h"
#include "devices/capture/capture_linux_rules.h"
#include "fixtures/worker_registry_fixture.h"
#include "loggers/internal_logger.h"
#include "test_assert.h"
#include "worker_messages.h"
#include "wwapi.h"

#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kTestWorkers = 3,
    kMaxMessages = 32,
    kMaxSockets  = 16,
    kMaxRules    = 16
};

typedef struct captured_message_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1, *arg2, *arg3;
    bool                         settled;
} captured_message_t;

typedef struct fake_queue_s
{
    int      fd;
    bool     open, ack_pending;
    uint32_t ack_sequence;
    int      ack_error;
    uint32_t stale_ack_sequence;
    int      stale_ack_error;
    uint32_t queue_limit;
    int      receive_buffer;
    int      receive_actual;
} fake_queue_t;

typedef struct fake_rule_s
{
    char comment[64];
    bool installed, steering;
} fake_rule_t;

typedef struct test_env_s
{
    master_pool_t         *large_master, *medium_master, *small_master;
    buffer_pool_t         *pools[kTestWorkers];
    wloop_t               *loops[kTestWorkers];
    test_worker_registry_t registry;
} test_env_t;

static captured_message_t messages[kMaxMessages];
static unsigned           message_count;
static fake_queue_t       sockets[kMaxSockets];
static fake_queue_t       probe_socket;
static unsigned           probe_count, probe_close_count;
static unsigned           socket_count, close_count, bind_count, failed_bind, receive_count;
static fake_rule_t        rules[kMaxRules];
static unsigned rule_count, installed_rules, steering_inserts, steering_deletes, single_inserts, failed_steering_insert;
static unsigned delivered_packets;
static device_reader_session_t *tracked_session;
static master_pool_t           *tracked_pool;
static sbuf_t                  *tracked_packet;
static unsigned                 session_frees, pool_destroys, packet_destroys;
static int                      initial_receive_actual, receive_cap, queue_length_error;
static bool                     refuse_receive_buffer, fail_receive_query, delay_length_ack, timeout_next_poll;
static bool                     refuse_copy_params;
static unsigned                 stale_acks_received;
static bool                     fail_probe_open, refuse_probe_buffer, fail_probe_query;
static char                     log_capture[64 * 1024];
static size_t                   log_capture_length;

int      __wrap_socket(int domain, int type, int protocol);
int      __wrap_bind(int fd, const struct sockaddr *address, socklen_t length);
int      __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
int      __real_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
int      __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *length);
int      __real_getsockopt(int fd, int level, int option, void *value, socklen_t *length);
int      __wrap_close(int fd);
int      __real_close(int fd);
ssize_t  __wrap_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *address,
                       socklen_t address_length);
ssize_t  __wrap_recvmsg(int fd, struct msghdr *message, int flags);
int      __wrap_poll(struct pollfd *fds, nfds_t count, int timeout);
uint64_t __wrap_fastRand64(void);
bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
void                           __real_memoryFree(void *pointer);
void                           __wrap_memoryFree(void *pointer);
void                           __real_masterpoolDestroy(master_pool_t *pool);
void                           __wrap_masterpoolDestroy(master_pool_t *pool);
void                           __real_sbufDestroy(sbuf_t *buffer);
void                           __wrap_sbufDestroy(sbuf_t *buffer);

static fake_queue_t *findSocket(int fd)
{
    if (probe_socket.open && probe_socket.fd == fd)
        return &probe_socket;
    for (unsigned i = 0; i < socket_count; ++i)
        if (sockets[i].open && sockets[i].fd == fd)
            return &sockets[i];
    return NULL;
}

static void captureLog(int level, const char *text, int length)
{
    discard level;
    if (text == NULL || length <= 0)
        return;
    const size_t count = min((size_t) length, sizeof(log_capture) - log_capture_length - 1);
    memoryCopy(log_capture + log_capture_length, text, count);
    log_capture_length += count;
    log_capture[log_capture_length] = '\0';
}

int __wrap_socket(int domain, int type, int protocol)
{
    require(domain == AF_NETLINK && protocol == NETLINK_NETFILTER, "unexpected socket family in Capture setup");
    require((type & (SOCK_NONBLOCK | SOCK_CLOEXEC)) == (SOCK_NONBLOCK | SOCK_CLOEXEC),
            "Capture queue setup lost nonblocking or close-on-exec flags");
    const bool probe = (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_DGRAM;
    if (probe && fail_probe_open)
    {
        errno = EMFILE;
        return -1;
    }
    require(socket_count < kMaxSockets, "too many queue sockets");
    const int fd = dup(STDERR_FILENO);
    require(fd >= 0, "unable to allocate inert queue descriptor");
    if (probe)
    {
        require(! probe_socket.open, "receive allowance probes overlapped");
        probe_socket = (fake_queue_t) {.fd = fd, .open = true, .receive_actual = initial_receive_actual};
        ++probe_count;
    }
    else
        sockets[socket_count++] = (fake_queue_t) {.fd = fd, .open = true, .receive_actual = initial_receive_actual};
    return fd;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    require(findSocket(fd) != NULL && findSocket(fd) != &probe_socket && length == sizeof(struct sockaddr_nl) &&
                address->sa_family == AF_NETLINK,
            "Capture bound an unexpected queue descriptor");
    return 0;
}

int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    fake_queue_t *queue = findSocket(fd);
    if (queue == NULL)
        return __real_setsockopt(fd, level, option, value, length);
    require(length == sizeof(int), "queue option has the wrong geometry");
    if (level == SOL_SOCKET && option == SO_RCVBUF)
    {
        memoryCopy(&queue->receive_buffer, value, sizeof(queue->receive_buffer));
        if (queue == &probe_socket ? refuse_probe_buffer : refuse_receive_buffer)
        {
            errno = EPERM;
            return -1;
        }
        queue->receive_actual = (int) min((uint64_t) queue->receive_buffer * 2U, (uint64_t) receive_cap);
    }
    else
        require(level == SOL_NETLINK && option == NETLINK_NO_ENOBUFS, "unexpected queue socket option");
    return 0;
}

int __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{
    fake_queue_t *queue = findSocket(fd);
    if (queue == NULL)
        return __real_getsockopt(fd, level, option, value, length);
    require(level == SOL_SOCKET && option == SO_RCVBUF && *length == sizeof(int), "unexpected receive-buffer readback");
    if (fail_receive_query || (queue == &probe_socket && fail_probe_query))
    {
        errno = EIO;
        return -1;
    }
    memoryCopy(value, &queue->receive_actual, sizeof(int));
    return 0;
}

int __wrap_close(int fd)
{
    fake_queue_t *queue = findSocket(fd);
    if (queue != NULL)
    {
        queue->open = false;
        if (queue == &probe_socket)
            ++probe_close_count;
        else
            ++close_count;
    }
    return __real_close(fd);
}

ssize_t __wrap_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *address,
                      socklen_t address_length)
{
    fake_queue_t *queue = findSocket(fd);
    require(queue != NULL && (flags & MSG_DONTWAIT) != 0, "configuration used an invalid or blocking queue send");
    require(address_length == sizeof(struct sockaddr_nl) && address->sa_family == AF_NETLINK,
            "configuration targeted an invalid Netlink address");
    const struct nlmsghdr *header = data;
    require(header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG) &&
                (header->nlmsg_flags & NLM_F_ACK) != 0,
            "fixture expected an acknowledged queue configuration message");
    const struct nfgenmsg *generic   = NLMSG_DATA(header);
    const struct nfattr   *attribute = NFM_NFA(generic);
    require(installed_rules == 0, "queue configuration overlapped active capture rules");
    if (queue->ack_pending)
    {
        require(queue->stale_ack_sequence == 0, "fixture overflowed its delayed ACK slot");
        queue->stale_ack_sequence = queue->ack_sequence;
        queue->stale_ack_error    = queue->ack_error;
    }
    queue->ack_pending               = true;
    queue->ack_sequence              = header->nlmsg_seq;
    queue->ack_error                 = 0;
    if (attribute->nfa_type == NFQA_CFG_CMD)
    {
        struct nfqnl_msg_config_cmd command;
        memoryCopy(&command, NFA_DATA(attribute), sizeof(command));
        require(command.command == NFQNL_CFG_CMD_BIND, "Capture unexpectedly altered global protocol binding");
        if (++bind_count == failed_bind)
            queue->ack_error = -EBUSY;
    }
    else if (attribute->nfa_type == NFQA_CFG_QUEUE_MAXLEN)
    {
        uint32_t value;
        memoryCopy(&value, NFA_DATA(attribute), sizeof(value));
        queue->ack_error = queue_length_error;
        if (queue_length_error == 0)
            queue->queue_limit = ntohl(value);
        if (delay_length_ack)
            timeout_next_poll = true;
    }
    else
    {
        require(attribute->nfa_type == NFQA_CFG_PARAMS, "unexpected queue configuration attribute");
        if (refuse_copy_params)
            queue->ack_error = -EPERM;
    }
    return (ssize_t) length;
}

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags)
{
    fake_queue_t *queue = findSocket(fd);
    require(queue != NULL && (flags & MSG_DONTWAIT) != 0, "receive used an invalid or blocking queue descriptor");
    ++receive_count;
    if (! queue->ack_pending)
    {
        errno = EAGAIN;
        return -1;
    }
    require(message->msg_iovlen == 1 && message->msg_iov[0].iov_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)),
            "configuration ACK storage is too small");
    struct nlmsghdr *header = message->msg_iov[0].iov_base;
    memoryZero(header, NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    header->nlmsg_len                         = NLMSG_LENGTH(sizeof(struct nlmsgerr));
    header->nlmsg_type                        = NLMSG_ERROR;
    const bool stale                          = queue->stale_ack_sequence != 0;
    header->nlmsg_seq                         = stale ? queue->stale_ack_sequence : queue->ack_sequence;
    struct nlmsgerr *ack                      = NLMSG_DATA(header);
    ack->error                                = stale ? queue->stale_ack_error : queue->ack_error;
    *(struct sockaddr_nl *) message->msg_name = (struct sockaddr_nl) {.nl_family = AF_NETLINK};
    message->msg_namelen                      = sizeof(struct sockaddr_nl);
    message->msg_flags                        = 0;
    if (stale)
    {
        queue->stale_ack_sequence = 0;
        ++stale_acks_received;
    }
    else
        queue->ack_pending = false;
    return header->nlmsg_len;
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    discard timeout;
    require(count == 1 && findSocket(fds[0].fd) != NULL && findSocket(fds[0].fd)->ack_pending &&
                (fds[0].events & POLLIN) != 0,
            "Capture waited outside exclusive acknowledged configuration");
    if (timeout_next_poll)
    {
        timeout_next_poll = false;
        return 0;
    }
    fds[0].revents = POLLIN;
    return 1;
}

uint64_t __wrap_fastRand64(void)
{
    return UINT64_C(0x1122334455667788);
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    require(strcmp(file, "iptables") == 0, "fixture unexpectedly invoked a host tuning command");
    memoryZero(out, sizeof(*out));
    out->exit_code = 0;
    if (strcmp(argv[3], "-S") == 0)
    {
        require(installed_rules == 0, "queue selection overlapped a live rule inventory");
        out->output     = stringDuplicate("-P INPUT ACCEPT\n");
        out->output_len = stringLength(out->output);
        return true;
    }
    require(options->progress == captureReaderService && options->progress_context != NULL,
            "firewall mutation lost inactive queue service");
    options->progress(options->progress_context);
    require(strcmp(argv[4], "INPUT") == 0 && strcmp(argv[12], "NFQUEUE") == 0, "fixture expected a Capture queue rule");
    const char *comment  = argv[10];
    const bool  steering = argv[16] != NULL;
    if (strcmp(argv[3], "-I") == 0)
    {
        if (steering && ++steering_inserts == failed_steering_insert)
        {
            out->exit_code = 1;
            return false;
        }
        if (! steering)
            ++single_inserts;
        require(rule_count < kMaxRules, "too many owned rules");
        fake_rule_t *rule = &rules[rule_count++];
        stringNPrintf(rule->comment, sizeof(rule->comment), "%s", comment);
        rule->installed = true;
        rule->steering  = steering;
        ++installed_rules;
        return true;
    }
    require(strcmp(argv[3], "-D") == 0, "unexpected firewall operation");
    for (unsigned i = 0; i < rule_count; ++i)
    {
        if (rules[i].installed && strcmp(rules[i].comment, comment) == 0)
        {
            require(rules[i].steering == steering, "rollback changed the steering predicate");
            rules[i].installed = false;
            --installed_rules;
            steering_deletes += steering;
            return true;
        }
    }
    require(false, "rollback attempted to delete an unowned rule");
    return false;
}

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    require(message_count < kMaxMessages && callback != NULL && cleanup != NULL, "invalid queued Capture message");
    messages[message_count++] = (captured_message_t) {wid, callback, cleanup, arg1, arg2, arg3, false};
    return kWorkerMessageSubmitAccepted;
}

void __wrap_memoryFree(void *pointer)
{
    if (pointer != NULL && pointer == tracked_session)
        ++session_frees;
    __real_memoryFree(pointer);
}

void __wrap_masterpoolDestroy(master_pool_t *pool)
{
    if (pool != NULL && pool == tracked_pool)
        ++pool_destroys;
    __real_masterpoolDestroy(pool);
}

void __wrap_sbufDestroy(sbuf_t *buffer)
{
    if (buffer != NULL && buffer == tracked_packet)
        ++packet_destroys;
    __real_sbufDestroy(buffer);
}

static void deliverPacket(capture_device_t *device, void *userdata, sbuf_t *buffer, wid_t wid)
{
    discard device;
    discard userdata;
    discard wid;
    ++delivered_packets;
    sbufDestroy(buffer);
}

static void resetCase(void)
{
    for (unsigned i = 0; i < message_count; ++i)
        require(messages[i].settled, "previous case retained a queued message");
    require(close_count == socket_count && installed_rules == 0, "previous case retained native ownership");
    require(probe_count == probe_close_count && ! probe_socket.open, "previous case retained a socket probe");
    memoryZero(messages, sizeof(messages));
    memoryZero(sockets, sizeof(sockets));
    memoryZero(rules, sizeof(rules));
    probe_count = probe_close_count = 0;
    probe_socket                    = (fake_queue_t) {0};
    message_count = socket_count = close_count = bind_count = failed_bind = receive_count = 0;
    rule_count = installed_rules = steering_inserts = steering_deletes = single_inserts = failed_steering_insert = 0;
    delivered_packets = session_frees = pool_destroys = packet_destroys = 0;
    tracked_session                                                     = NULL;
    tracked_pool                                                        = NULL;
    tracked_packet                                                      = NULL;
    initial_receive_actual                                              = 256 * 1024;
    receive_cap                                                         = INT_MAX;
    queue_length_error                                                  = 0;
    refuse_receive_buffer = fail_receive_query = delay_length_ack = timeout_next_poll = refuse_copy_params = false;
    stale_acks_received                                                                                    = 0;
    fail_probe_open = refuse_probe_buffer = fail_probe_query            = false;
    log_capture_length                                                  = 0;
    log_capture[0]                                                      = '\0';
    GSTATE.capturedevice_queue_start_number                             = 77;
}

static void cancelMessages(void)
{
    testWorkerUnbindWID();
    for (unsigned i = 0; i < message_count; ++i)
    {
        captured_message_t *message = &messages[i];
        if (! message->settled)
        {
            message->settled = true;
            message->cleanup(message->arg1, message->arg2, message->arg3, kWorkerMessageCancelQuiesced);
        }
    }
    testWorkerBindWID(0);
}

static capture_device_t *createDeviceWithPolicy(device_fragment_policy_t policy)
{
    ipmask_t range = {0};
    require(ipaddr_aton("192.0.2.0", &range.ip) && ipaddr_aton("255.255.255.0", &range.mask), "invalid fixture CIDR");
    const capture_protocol_filter_t filter = {0};
    capture_device_t               *device =
        caputredeviceCreate("capture-lifecycle-test", &range, 1, true, false, &filter, NULL, deliverPacket, policy);
    require(device != NULL, "public Capture construction failed");
    return device;
}

static capture_device_t *createDevice(void)
{
    return createDeviceWithPolicy(kDeviceFragmentPreserve);
}

static void testQueuedCancellationAfterDeviceDestruction(void)
{
    resetCase();
    capture_device_t *device = createDevice();
    tracked_session          = device->reader_session;
    tracked_pool             = tracked_session->message_pool;
    require(deviceReaderSessionBegin(tracked_session) != 0, "session generation did not open");
    tracked_packet = sbufCreate(64);
    sbufSetLength(tracked_packet, 64);
    require(deviceReaderSessionTryPost(tracked_session, 1, &tracked_packet, 1) == kDeviceReaderPostAccepted,
            "bounded FIFO did not accept the packet");
    require(message_count == 1 && atomicLoadRelaxed(&tracked_session->refcount) == 3,
            "FIFO message and scheduled token did not retain independent session references");
    capturedeviceDestroy(device);
    require(atomicLoadRelaxed(&tracked_session->refcount) == 2 && session_frees == 0 && pool_destroys == 0,
            "device destruction reclaimed the session retained by queued FIFO work");
    require(tracked_session->reader_buffer_pool == NULL && atomicLoadRelaxed(&tracked_session->output_packets) == 1,
            "device destruction lost queued credits or retained the retired producer pool");
    cancelMessages();
    require(session_frees == 1 && pool_destroys == 1 && packet_destroys == 1 && delivered_packets == 0,
            "foreign cancellation did not settle packet, session and message pool exactly once");
}

static void requireStartedQueues(capture_device_t *device, unsigned count)
{
    require(capturedeviceIsUp(device) && device->queue_count == count && installed_rules == count,
            "Capture activated the wrong queue/rule count");
    require(message_count == count, "Capture scheduled the wrong number of worker readers");
    for (unsigned i = 0; i < count; ++i)
    {
        require(messages[i].wid == i, "queue activation selected the wrong worker");
        fake_queue_t *queue = findSocket(device->queues[i].fd);
        require(queue != NULL && queue->queue_limit == kNetfilterQueueLen / count &&
                    queue->receive_buffer == kNetfilterSocketRecvBuffer / (int) count,
                "active queue set did not share the device-wide kernel budgets");
    }
}

static void finishDevice(capture_device_t *device)
{
    capturedeviceDestroy(device);
    require(installed_rules == 0 && close_count == socket_count, "device destruction retained rules or queue sockets");
    require(probe_count == probe_close_count && ! probe_socket.open, "sizing retained an unbound probe socket");
    cancelMessages();
    require(delivered_packets == 0, "inactive setup or late cleanup published a packet");
}

static void testQueueSetupAndFallback(void)
{
    resetCase();
    capture_device_t *device = createDevice();
    require(caputredeviceBringUp(device), "multiqueue startup failed");
    requireStartedQueues(device, kTestWorkers);
    require(socket_count == kTestWorkers && steering_inserts == kTestWorkers,
            "multiqueue setup omitted a queue or predicate");
    finishDevice(device);

    resetCase();
    device = createDevice();
    capturedeviceSetMultiQueue(device, false);
    require(caputredeviceBringUp(device), "explicit single-queue startup failed");
    requireStartedQueues(device, 1);
    require(socket_count == 1 && steering_inserts == 0 && single_inserts == 1,
            "multi-queue:false still opened extra queues or steering predicates");
    finishDevice(device);

    resetCase();
    device      = createDevice();
    failed_bind = 2;
    require(caputredeviceBringUp(device), "extra queue bind refusal did not fall back");
    requireStartedQueues(device, 1);
    require(socket_count == 2 && close_count == 1 && steering_inserts == 0 && single_inserts == 1,
            "extra queue bind fallback retained an unused queue or steering rule");
    finishDevice(device);

    resetCase();
    device                 = createDevice();
    failed_steering_insert = 2;
    require(caputredeviceBringUp(device), "steering rule refusal did not fall back");
    requireStartedQueues(device, 1);
    require(socket_count == kTestWorkers && close_count == kTestWorkers - 1 && steering_inserts == 2 &&
                steering_deletes == 1 && single_inserts == 1,
            "steering fallback did not roll back the exact partial rule/queue inventory");
    finishDevice(device);

    resetCase();
    device      = createDevice();
    failed_bind = 1;
    require(! caputredeviceBringUp(device), "first queue bind refusal was accepted");
    require(! capturedeviceIsUp(device) && device->queue_count == 0 && device->reader == NULL &&
                captureLifecycleLoad(&device->lifecycle) == kCaptureLifecycleDown && installed_rules == 0 &&
                socket_count == 1 && close_count == 1 && message_count == 0,
            "first queue failure did not return to a fully settled Down state");
    finishDevice(device);
}

static void testKernelQueueTuning(void)
{
    resetCase();
    capture_device_t *device = createDevice();
    capturedeviceConfigureKernelQueue(device, true, 128U * 1024U, 128U * 1024U * 1024U);
    require(caputredeviceBringUp(device), "explicit kernel queue sizing prevented startup");
    for (unsigned i = 0; i < device->queue_count; ++i)
    {
        const fake_queue_t *queue = findSocket(device->queues[i].fd);
        require(queue->queue_limit == 128U * 1024U / kTestWorkers &&
                    queue->receive_buffer == (int) (128U * 1024U * 1024U / kTestWorkers) &&
                    device->queues[i].queue_limit_known,
                "explicit device-wide budgets were not divided across the final native queues");
    }
    require(strstr(log_capture, "packet source=override") != NULL &&
                strstr(log_capture, "receive source=override") != NULL &&
                strstr(log_capture, "effective=ACK-confirmed") != NULL &&
                strstr(log_capture, "actual=89478484 (Linux doubled accounting)") != NULL,
            "startup log lost override provenance, acknowledged limit or actual doubled socket allowance");
    finishDevice(device);

    resetCase();
    device = createDevice();
    capturedeviceConfigureKernelQueue(device, false, INT_MAX, INT_MAX);
    require(caputredeviceBringUp(device), "disabled tuner prevented startup");
    requireStartedQueues(device, kTestWorkers);
    require(strstr(log_capture, "packet source=disabled") != NULL &&
                strstr(log_capture, "receive source=disabled") != NULL,
            "disabled tuning was logged as automatic or overridden");
    finishDevice(device);

    resetCase();
    device = createDevice();
    capturedeviceConfigureKernelQueue(device, true, 1, 1);
    require(caputredeviceBringUp(device), "small override prevented startup");
    requireStartedQueues(device, kTestWorkers);
    finishDevice(device);

    resetCase();
    initial_receive_actual = 256 * 1024 * 1024;
    device                 = createDevice();
    require(caputredeviceBringUp(device), "larger existing socket buffer prevented startup");
    for (unsigned i = 0; i < device->queue_count; ++i)
    {
        const fake_queue_t *queue = findSocket(device->queues[i].fd);
        require(queue->receive_buffer == 0 && queue->receive_actual == initial_receive_actual,
                "tuning reduced an existing larger socket buffer");
    }
    finishDevice(device);

    resetCase();
    initial_receive_actual = 8 * 1024 * 1024;
    receive_cap            = 2 * 1024 * 1024;
    device                 = createDevice();
    require(caputredeviceBringUp(device), "socket exceeding host ceiling prevented startup");
    for (unsigned i = 0; i < device->queue_count; ++i)
    {
        const fake_queue_t *queue = findSocket(device->queues[i].fd);
        require(queue->receive_buffer == 0 && queue->receive_actual == initial_receive_actual,
                "larger target reduced an existing socket to the host ceiling");
    }
    require(probe_count == kTestWorkers && strstr(log_capture, "receive source=auto") != NULL &&
                strstr(log_capture, "SO_RCVBUF request=0, actual=8388608") != NULL,
            "preserved socket allowance was not probed or logged with automatic provenance");
    finishDevice(device);

    resetCase();
    device = createDevice();
    capturedeviceConfigureKernelQueue(device, true, 128U * 1024U, 128U * 1024U * 1024U);
    failed_steering_insert = 2;
    require(caputredeviceBringUp(device) && device->queue_count == 1, "explicit budget steering fallback failed");
    const fake_queue_t *queue = findSocket(device->queues[0].fd);
    require(queue->queue_limit == 128U * 1024U && queue->receive_buffer == 128 * 1024 * 1024 &&
                device->queues[0].queue_limit_known,
            "fallback did not recompute budgets for its surviving queue");
    finishDevice(device);
}

static void testKernelQueueTuningFailures(void)
{
    resetCase();
    queue_length_error       = -EPERM;
    refuse_receive_buffer    = true;
    capture_device_t *device = createDevice();
    require(caputredeviceBringUp(device) && device->queue_count == kTestWorkers,
            "optional queue sizing refusal disabled working multiqueue capture");
    require(strstr(log_capture, "effective=unknown") != NULL,
            "failed queue sizing was logged as an effective accepted limit");
    for (unsigned i = 0; i < device->queue_count; ++i)
        require(! device->queues[i].queue_limit_known &&
                    findSocket(device->queues[i].fd)->receive_actual == initial_receive_actual,
                "refused sizing was reported as accepted or changed the existing socket buffer");
    finishDevice(device);

    resetCase();
    delay_length_ack = true;
    device           = createDevice();
    require(caputredeviceBringUp(device) && stale_acks_received == kTestWorkers,
            "required copy setup did not consume delayed optional-sizing ACKs");
    for (unsigned i = 0; i < device->queue_count; ++i)
        require(! device->queues[i].queue_limit_known && ! findSocket(device->queues[i].fd)->ack_pending,
                "timed-out sizing was called confirmed or left an ACK for the packet reader");
    finishDevice(device);

    resetCase();
    delay_length_ack = refuse_copy_params = true;
    device                                = createDevice();
    require(! caputredeviceBringUp(device) && installed_rules == 0 && close_count == socket_count,
            "unusable configuration channel activated capture rules");
    finishDevice(device);

    resetCase();
    fail_receive_query = true;
    device             = createDevice();
    require(caputredeviceBringUp(device), "receive-buffer query failure disabled a working queue");
    for (unsigned i = 0; i < device->queue_count; ++i)
        require(findSocket(device->queues[i].fd)->receive_buffer == 0,
                "unknown existing socket buffer was overwritten");
    require(strstr(log_capture, "actual=unavailable") != NULL,
            "failed socket readback was logged as a numeric effective allowance");
    finishDevice(device);

    for (unsigned failure = 0; failure < 3; ++failure)
    {
        resetCase();
        fail_probe_open     = failure == 0;
        refuse_probe_buffer = failure == 1;
        fail_probe_query    = failure == 2;
        device              = createDevice();
        require(caputredeviceBringUp(device), "receive allowance probe failure disabled working capture");
        for (unsigned i = 0; i < device->queue_count; ++i)
            require(findSocket(device->queues[i].fd)->receive_buffer == 0 &&
                        findSocket(device->queues[i].fd)->receive_actual == initial_receive_actual,
                    "failed probe permitted a potentially shrinking socket write");
        finishDevice(device);
    }

    resetCase();
    receive_cap = 512 * 1024;
    device      = createDevice();
    require(caputredeviceBringUp(device), "host receive-buffer cap disabled a working queue");
    for (unsigned i = 0; i < device->queue_count; ++i)
        require(findSocket(device->queues[i].fd)->receive_actual == receive_cap,
                "fixture failed to exercise clamped socket-buffer readback");
    finishDevice(device);
}

static void testFullRestartRejectsStaleActivation(test_env_t *env)
{
    resetCase();
    capture_device_t *device = createDevice();
    capturedeviceSetMultiQueue(device, false);
    require(caputredeviceBringUp(device) && message_count == 1, "first startup did not queue activation");
    const uint32_t first_generation = atomicLoadRelaxed(&device->reader_session->generation);
    require(caputredeviceBringDown(device), "first generation did not stop cleanly");
    require(caputredeviceBringUp(device) && message_count == 2 &&
                atomicLoadRelaxed(&device->reader_session->generation) != first_generation,
            "restart did not publish a distinct generation");
    const unsigned      before = receive_count;
    captured_message_t *stale  = &messages[0];
    stale->settled             = true;
    stale->callback(&env->registry.slots[stale->wid], stale->arg1, stale->arg2, stale->arg3);
    require(receive_count == before && capturedeviceIsUp(device) && device->queue_count == 1 && installed_rules == 1,
            "old activation touched the restarted native queue or current lifecycle");
    finishDevice(device);
}

static sbuf_t *makePaddingFragment(bool final)
{
    sbuf_t  *buffer = sbufCreateWithPadding(28, 256);
    uint8_t *packet = sbufGetMutablePtr(buffer);
    memoryZero(packet, 28);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 17;
    PUT_BE16(packet + 2, 28);
    PUT_BE16(packet + 4, 0x1234);
    PUT_BE16(packet + 6, final ? 1 : 0x2000);
    PUT_BE32(packet + 12, UINT32_C(0xc0000201));
    PUT_BE32(packet + 16, UINT32_C(0xc6336402));
    if (! final)
    {
        PUT_BE16(packet + 20, 12345);
        PUT_BE16(packet + 22, 443);
        PUT_BE16(packet + 24, 16);
    }
    else
        memorySet(packet + 20, 0x5a, 8);
    uint32_t sum = 0;
    for (unsigned offset = 0; offset < 20; offset += 2)
        sum += GET_BE16(packet + offset);
    while (sum >> 16)
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    PUT_BE16(packet + 10, (uint16_t) ~sum);
    sbufSetLength(buffer, 28);
    return buffer;
}

static void testFinalizedPaddingAndReassembly(void)
{
    resetCase();
    capture_device_t *device = createDeviceWithPolicy(kDeviceFragmentReassemble);
    /* Finalization can increase worker padding after backend construction. */
    globalstateUpdateAllocationPadding(256);
    require(caputredeviceBringUp(device), "padded Capture startup failed");
    require(bufferpoolGetSmallBufferPadding(device->reader_buffer_pool) >= 256 &&
                bufferpoolGetLargeBufferPadding(device->reader_buffer_pool) >= 256,
            "BringUp did not copy finalized worker padding before coordinator receive service");

    device_frag_affinity_result_t fragment;
    sbuf_t                       *buffer = makePaddingFragment(false);
    require(
        deviceFragAffinityOffer(
            device->reader_session->frag_affinity, sbufGetRawPtr(buffer), sbufGetLength(buffer), buffer, &fragment) ==
            kDeviceFragAffinityStaged,
        "first padding-test fragment did not enter reassembly");
    buffer = makePaddingFragment(true);
    require(
        deviceFragAffinityOffer(
            device->reader_session->frag_affinity, sbufGetRawPtr(buffer), sbufGetLength(buffer), buffer, &fragment) ==
            kDeviceFragAffinityComplete,
        "padding-test fragments did not produce a complete datagram");
    require(sbufGetLength(fragment.completed) == 36 && sbufGetLeftCapacity(fragment.completed) >= 256,
            "shared reassembly lost finalized chain padding");
    const uint8_t *packet = sbufGetRawPtr(fragment.completed);
    require(GET_BE16(packet + 20) == 12345 && GET_BE16(packet + 24) == 16 && packet[28] == 0x5a && packet[35] == 0x5a,
            "padded reassembly changed packet bytes");
    sbufDestroy(fragment.completed);
    finishDevice(device);
    globalstateUpdateAllocationPadding(0);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master  = masterpoolCreateWithCapacity(16);
    env->medium_master = masterpoolCreateWithCapacity(16);
    env->small_master  = masterpoolCreateWithCapacity(16);
    for (wid_t wid = 0; wid < kTestWorkers; ++wid)
    {
        env->pools[wid] = bufferpoolCreate(env->large_master,
                                           env->medium_master,
                                           env->small_master,
                                           16,
                                           8192,
                                           MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                           4096,
                                           8192,
                                           8192);
        require(env->pools[wid] != NULL, "worker pool construction failed");
        env->loops[wid] = (wloop_t *) (void *) &env->pools[wid];
    }
    GSTATE.shortcut_buffer_pools          = env->pools;
    GSTATE.shortcut_loops                 = env->loops;
    GSTATE.masterpool_buffer_pools_large  = env->large_master;
    GSTATE.masterpool_buffer_pools_medium = env->medium_master;
    GSTATE.masterpool_buffer_pools_small  = env->small_master;
    GSTATE.workers_count                  = kTestWorkers;
    GSTATE.ram_profile                    = 1;
    testWorkerRegistryInstall(&env->registry);
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    resetCase();
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&env->registry);
    GSTATE.shortcut_buffer_pools          = NULL;
    GSTATE.shortcut_loops                 = NULL;
    GSTATE.masterpool_buffer_pools_large  = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;
    GSTATE.masterpool_buffer_pools_small  = NULL;
    GSTATE.workers_count                  = 0;
    for (unsigned wid = 0; wid < kTestWorkers; ++wid)
        bufferpoolDestroy(env->pools[wid]);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->medium_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->medium_master);
    masterpoolDestroy(env->small_master);
}

int main(void)
{
    testCaseSet("capture_linux_message_lifetime_test");
    logger_t *logger = loggerCreate();
    loggerSetHandler(logger, captureLog);
    setInternalLogger(logger);
    test_env_t env;
    envSetup(&env);
    testQueuedCancellationAfterDeviceDestruction();
    testQueueSetupAndFallback();
    testKernelQueueTuning();
    testKernelQueueTuningFailures();
    testFullRestartRejectsStaleActivation(&env);
    testFinalizedPaddingAndReassembly();
    envTeardown(&env);
    internaloggerDestroy();
    return 0;
}
