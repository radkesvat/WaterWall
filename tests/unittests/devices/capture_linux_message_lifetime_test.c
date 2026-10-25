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
    uint32_t queue_limit;
    int      receive_buffer;
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
static unsigned           socket_count, close_count, bind_count, failed_bind, receive_count;
static fake_rule_t        rules[kMaxRules];
static unsigned rule_count, installed_rules, steering_inserts, steering_deletes, single_inserts, failed_steering_insert;
static unsigned delivered_packets;
static device_reader_session_t *tracked_session;
static master_pool_t           *tracked_pool;
static sbuf_t                  *tracked_packet;
static unsigned                 session_frees, pool_destroys, packet_destroys;

int      __wrap_socket(int domain, int type, int protocol);
int      __wrap_bind(int fd, const struct sockaddr *address, socklen_t length);
int      __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
int      __real_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
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
    for (unsigned i = 0; i < socket_count; ++i)
        if (sockets[i].open && sockets[i].fd == fd)
            return &sockets[i];
    return NULL;
}

int __wrap_socket(int domain, int type, int protocol)
{
    require(domain == AF_NETLINK && protocol == NETLINK_NETFILTER, "unexpected socket family in Capture setup");
    require((type & (SOCK_NONBLOCK | SOCK_CLOEXEC)) == (SOCK_NONBLOCK | SOCK_CLOEXEC),
            "Capture queue setup lost nonblocking or close-on-exec flags");
    require(socket_count < kMaxSockets, "too many queue sockets");
    const int fd = dup(STDERR_FILENO);
    require(fd >= 0, "unable to allocate inert queue descriptor");
    sockets[socket_count++] = (fake_queue_t) {.fd = fd, .open = true};
    return fd;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    require(findSocket(fd) != NULL && length == sizeof(struct sockaddr_nl) && address->sa_family == AF_NETLINK,
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
        memoryCopy(&queue->receive_buffer, value, sizeof(queue->receive_buffer));
    else
        require(level == SOL_NETLINK && option == NETLINK_NO_ENOBUFS, "unexpected queue socket option");
    return 0;
}

int __wrap_close(int fd)
{
    fake_queue_t *queue = findSocket(fd);
    if (queue != NULL)
    {
        queue->open = false;
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
        queue->queue_limit = ntohl(value);
    }
    else
        require(attribute->nfa_type == NFQA_CFG_PARAMS, "unexpected queue configuration attribute");
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
    header->nlmsg_seq                         = queue->ack_sequence;
    struct nlmsgerr *ack                      = NLMSG_DATA(header);
    ack->error                                = queue->ack_error;
    *(struct sockaddr_nl *) message->msg_name = (struct sockaddr_nl) {.nl_family = AF_NETLINK};
    message->msg_namelen                      = sizeof(struct sockaddr_nl);
    message->msg_flags                        = 0;
    queue->ack_pending                        = false;
    return header->nlmsg_len;
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    discard timeout;
    require(count == 1 && findSocket(fds[0].fd) != NULL && findSocket(fds[0].fd)->ack_pending &&
                (fds[0].events & POLLIN) != 0,
            "Capture waited outside exclusive acknowledged configuration");
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
    memoryZero(messages, sizeof(messages));
    memoryZero(sockets, sizeof(sockets));
    memoryZero(rules, sizeof(rules));
    message_count = socket_count = close_count = bind_count = failed_bind = receive_count = 0;
    rule_count = installed_rules = steering_inserts = steering_deletes = single_inserts = failed_steering_insert = 0;
    delivered_packets = session_frees = pool_destroys = packet_destroys = 0;
    tracked_session                                                     = NULL;
    tracked_pool                                                        = NULL;
    tracked_packet                                                      = NULL;
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
    require(capturedeviceIsUp(device) && device->queue_count == count &&
                installed_rules == (count > 1 ? count * 2 : count),
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
    cancelMessages();
    require(delivered_packets == 0, "inactive setup or late cleanup published a packet");
}

static void testQueueSetupAndFallback(void)
{
    resetCase();
    capture_device_t *device = createDevice();
    require(caputredeviceBringUp(device), "multiqueue startup failed");
    requireStartedQueues(device, kTestWorkers);
    require(socket_count == kTestWorkers && steering_inserts == kTestWorkers * 2,
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
    device                 = createDevice();
    failed_steering_insert = kTestWorkers + 2;
    require(caputredeviceBringUp(device), "opaque nth rule refusal did not fall back");
    requireStartedQueues(device, 1);
    require(steering_inserts == kTestWorkers + 2 && steering_deletes == kTestWorkers + 1 && single_inserts == 1,
            "opaque rule fallback did not retire both partial rule sets");
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
    test_env_t env;
    envSetup(&env);
    testQueuedCancellationAfterDeviceDestruction();
    testQueueSetupAndFallback();
    testFullRestartRejectsStaleActivation(&env);
    testFinalizedPaddingAndReassembly();
    envTeardown(&env);
    return 0;
}
