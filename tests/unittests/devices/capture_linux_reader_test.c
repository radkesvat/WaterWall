/*
 * Covers: Linux capture worker readers, nonblocking verdict ownership, bounded
 * draining, capacity resume, watcher failure and generation settlement.
 * Setup: Real reader/session/WIO/event-loop/process-supervisor implementations;
 * UNIX datagrams substitute for NFQUEUE transport. Worker messages are retained
 * explicitly to exercise cancellation and delivery ordering without threads.
 * Cases: worker-zero fallback and two queues, batched reads/verdicts, short sends,
 * bounded readiness/prepared storage, verdict EAGAIN/EINTR, stop-to-ACCEPT,
 * capacity resume, mixed malformed/truncated input, startup refusal, watcher
 * failure, stale tokens, delayed settlement after destruction, and coordinator
 * command-time service.
 * Limits: This fixture does not prove kernel NFQUEUE setup or firewall steering.
 * CTest: waterwall.capture_linux_reader_unit
 */
#include "devices/capture/capture_linux_nfqueue.h"
#include "devices/device_flow_affinity.h"
#include "devices/device_pool.h"
#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"
#include "wloop_internal.h"
#include "worker_messages.h"
#include "wwapi.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kWorkers    = 2,
    kMessages   = 2048,
    kPacketIds  = 2048,
    kFirstQueue = 77,
    kSendSteps  = 8
};

typedef struct captured_message_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *args[3];
    bool                         settled;
} captured_message_t;

typedef struct queue_probe_s
{
    int      fd;
    int      peer;
    wid_t    owner;
    unsigned reads;
    unsigned read_packets;
    unsigned read_batches;
    unsigned largest_read;
    unsigned largest_receive_request;
    int      read_error;
    unsigned read_errors;
    unsigned verdict_attempts;
    unsigned verdicts;
    unsigned verdict_batches;
    unsigned largest_verdict_batch;
    unsigned cumulative_attempts;
    uint32_t cumulative_boundary;
    int      verdict_error;
    int      send_steps[kSendSteps];
    unsigned send_step_count;
    unsigned send_step;
    wio_t   *io;
    wio_cb   callback;
    unsigned packet_ids[kPacketIds];
    unsigned injected_packets;
} queue_probe_t;

typedef struct reader_fixture_s
{
    test_worker_registry_t     registry;
    master_pool_t             *large;
    master_pool_t             *medium;
    master_pool_t             *small;
    master_pool_t             *wio_master;
    threadsafe_generic_pool_t *wio_pools[kWorkers];
    buffer_pool_t             *pools[kWorkers];
    wloop_t                   *loops[kWorkers];
    queue_probe_t              queues[kWorkers];
    captured_message_t         messages[kMessages];
    unsigned                   message_count;
    unsigned                   reject_post;
    unsigned                   thread_calls;
    unsigned                   shutdown_calls;
    bool                       fail_add;
    bool                       coordinator;
    int                        command_release_fd;
    bool                       release_verdict_after_peer;
    uint32_t                   verdicts[kPacketIds];
    unsigned                   deliveries[kWorkers];
    unsigned                   delivery_ids[kWorkers][kPacketIds];
    unsigned                   packet_lengths[kPacketIds];
    uint16_t                   required_padding;
    void                      *tracked_generation;
    void                      *tracked_session;
    unsigned                   generation_frees;
    unsigned                   session_frees;
} reader_fixture_t;

static reader_fixture_t fixture;

ssize_t __real_recvmsg(int fd, struct msghdr *message, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags);
int     __real_recvmmsg(int fd, struct mmsghdr *messages, unsigned count, int flags, struct timespec *timeout);
int     __wrap_recvmmsg(int fd, struct mmsghdr *messages, unsigned count, int flags, struct timespec *timeout);
int     __real_sendmmsg(int fd, struct mmsghdr *messages, unsigned count, int flags);
int     __wrap_sendmmsg(int fd, struct mmsghdr *messages, unsigned count, int flags);
ssize_t __real_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *address,
                      socklen_t address_length);
ssize_t __wrap_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *address,
                      socklen_t address_length);
int     __real_wioAdd(wio_t *io, wio_cb callback, int events);
int     __wrap_wioAdd(wio_t *io, wio_cb callback, int events);
wio_t  *__real_wioGet(wloop_t *loop, int fd);
wio_t  *__wrap_wioGet(wloop_t *loop, int fd);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes, void *(*routine)(void *), void *context);
bool                           __wrap_requestProgramShutdown(int code);
_Noreturn void                 __wrap_abortProgramNow(int code);
void                           __real_memoryFree(void *pointer);
void                           __wrap_memoryFree(void *pointer);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);

static int queueIndex(int fd)
{
    for (unsigned i = 0; i < kWorkers; ++i)
        if (fixture.queues[i].fd == fd)
            return (int) i;
    return -1;
}

static void requireQueueOwner(unsigned index)
{
    require(fixture.coordinator || (currentThreadOwnsWorker(fixture.queues[index].owner) &&
                                    wloopCurrentThreadInNormalCallback(fixture.loops[fixture.queues[index].owner])),
            "native receive/verdict escaped its owner callback");
}

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags)
{
    const int index = queueIndex(fd);
    if (index < 0)
        return __real_recvmsg(fd, message, flags);
    requireQueueOwner((unsigned) index);
    require((flags & MSG_DONTWAIT) != 0, "capture receive may block");
    ++fixture.queues[index].reads;
    const ssize_t result = __real_recvmsg(fd, message, flags);
    if (result >= 0)
    {
        ++fixture.queues[index].read_packets;
        require(message->msg_name != NULL, "capture omitted sender storage");
        *(struct sockaddr_nl *) message->msg_name = (struct sockaddr_nl) {.nl_family = AF_NETLINK};
        message->msg_namelen                      = sizeof(struct sockaddr_nl);
    }
    return result;
}

int __wrap_recvmmsg(int fd, struct mmsghdr *messages, unsigned count, int flags, struct timespec *timeout)
{
    const int index = queueIndex(fd);
    if (index < 0)
        return __real_recvmmsg(fd, messages, count, flags, timeout);
    requireQueueOwner((unsigned) index);
    require((flags & (MSG_DONTWAIT | MSG_TRUNC)) == (MSG_DONTWAIT | MSG_TRUNC) && timeout == NULL,
            "capture batch receive may wait or hide truncation");
    require(count > 0 && count <= 256, "capture receive batch exceeded its packet bound");
    queue_probe_t *queue = &fixture.queues[index];
    ++queue->reads;
    ++queue->read_batches;
    if (count > queue->largest_receive_request)
        queue->largest_receive_request = count;
    if (queue->read_errors != 0)
    {
        --queue->read_errors;
        errno = queue->read_error;
        return -1;
    }
    const int result = __real_recvmmsg(fd, messages, count, flags, timeout);
    if (result <= 0)
        return result;
    queue->read_packets += (unsigned) result;
    if ((unsigned) result > queue->largest_read)
        queue->largest_read = (unsigned) result;
    for (int i = 0; i < result; ++i)
    {
        struct msghdr *message = &messages[i].msg_hdr;
        require(message->msg_name != NULL, "capture batch omitted sender storage");
        *(struct sockaddr_nl *) message->msg_name = (struct sockaddr_nl) {.nl_family = AF_NETLINK};
        message->msg_namelen                      = sizeof(struct sockaddr_nl);
    }
    return result;
}

static void commitVerdict(unsigned index, uint32_t id, uint32_t verdict)
{
    require(id > 0 && id < kPacketIds && fixture.verdicts[id] == UINT32_MAX, "packet received a duplicate verdict");
    fixture.verdicts[id] = verdict;
    ++fixture.queues[index].verdicts;
    if (fixture.release_verdict_after_peer && id == 2 && fixture.verdicts[id] == NF_ACCEPT)
    {
        fixture.queues[0].verdict_error    = 0;
        fixture.release_verdict_after_peer = false;
    }
    if (fixture.command_release_fd >= 0 && fixture.verdicts[1] == NF_ACCEPT && fixture.verdicts[2] == NF_ACCEPT)
    {
        require(write(fixture.command_release_fd, "x", 1) == 1,
                "two-device queue service could not release the stalled command");
        fixture.command_release_fd = -1;
    }
}

ssize_t __wrap_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *address,
                      socklen_t address_length)
{
    const int index = queueIndex(fd);
    if (index < 0)
        return __real_sendto(fd, data, length, flags, address, address_length);
    requireQueueOwner((unsigned) index);
    require((flags & MSG_DONTWAIT) != 0, "capture verdict may block");
    const struct nlmsghdr *header     = data;
    const bool             cumulative = header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT_BATCH);
    require(cumulative || header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT),
            "unexpected netlink message");
    const struct nfgenmsg *generic = NLMSG_DATA(header);
    require(ntohs(generic->res_id) == kFirstQueue + index, "verdict used another queue number");
    const struct nfattr         *attribute = NFM_NFA(generic);
    struct nfqnl_msg_verdict_hdr verdict;
    require(NFA_PAYLOAD(attribute) == sizeof(verdict), "invalid verdict shape");
    memoryCopy(&verdict, NFA_DATA(attribute), sizeof(verdict));
    ++fixture.queues[index].verdict_attempts;
    if (cumulative)
        ++fixture.queues[index].cumulative_attempts;
    if (fixture.queues[index].verdict_error != 0)
    {
        errno = fixture.queues[index].verdict_error;
        return -1;
    }
    const uint32_t id = ntohl(verdict.id);
    if (cumulative)
    {
        queue_probe_t *queue = &fixture.queues[index];
        unsigned       last  = 0;
        while (last < queue->injected_packets && queue->packet_ids[last] != id)
            ++last;
        require(last < queue->read_packets && fixture.verdicts[id] == UINT32_MAX,
                "cumulative verdict boundary was unread, missing or already committed");
        for (unsigned i = 0; i <= last; ++i)
            if (fixture.verdicts[queue->packet_ids[i]] == UINT32_MAX)
                commitVerdict((unsigned) index, queue->packet_ids[i], ntohl(verdict.verdict));
        queue->cumulative_boundary = id;
    }
    else
        commitVerdict((unsigned) index, id, ntohl(verdict.verdict));
    return (ssize_t) length;
}

int __wrap_sendmmsg(int fd, struct mmsghdr *messages, unsigned count, int flags)
{
    const int index = queueIndex(fd);
    if (index < 0)
        return __real_sendmmsg(fd, messages, count, flags);
    requireQueueOwner((unsigned) index);
    require((flags & MSG_DONTWAIT) != 0, "capture verdict batch may block");
    require(count > 0 && count <= 256, "capture verdict batch exceeded its packet bound");
    queue_probe_t *queue = &fixture.queues[index];
    ++queue->verdict_batches;
    if (count > queue->largest_verdict_batch)
        queue->largest_verdict_batch = count;
    if (queue->send_step < queue->send_step_count)
    {
        const int step = queue->send_steps[queue->send_step++];
        if (step < 0)
        {
            ++queue->verdict_attempts;
            errno = -step;
            return -1;
        }
        require(step > 0, "invalid scripted verdict batch completion");
        if ((unsigned) step < count)
            count = (unsigned) step;
    }
    for (unsigned i = 0; i < count; ++i)
    {
        struct msghdr *message = &messages[i].msg_hdr;
        require(message->msg_iovlen == 1, "verdict batch changed message geometry");
        const ssize_t sent = __wrap_sendto(fd,
                                           message->msg_iov[0].iov_base,
                                           message->msg_iov[0].iov_len,
                                           flags,
                                           message->msg_name,
                                           message->msg_namelen);
        if (sent < 0)
            return i == 0 ? -1 : (int) i;
        messages[i].msg_len = (unsigned) sent;
    }
    return (int) count;
}

wio_t *__wrap_wioGet(wloop_t *loop, int fd)
{
    wio_t    *io    = __real_wioGet(loop, fd);
    const int index = queueIndex(fd);
    if (index >= 0)
    {
        require(currentThreadOwnsWorker(fixture.queues[index].owner), "watcher created by the wrong worker");
        fixture.queues[index].io = io;
    }
    return io;
}

int __wrap_wioAdd(wio_t *io, wio_cb callback, int events)
{
    const int index = queueIndex(wioGetFD(io));
    if (index >= 0)
    {
        require(currentThreadOwnsWorker(fixture.queues[index].owner), "watcher registered by the wrong worker");
        fixture.queues[index].io       = io;
        fixture.queues[index].callback = callback;
        if (fixture.fail_add)
        {
            fixture.fail_add = false;
            errno            = ENOSPC;
            return -1;
        }
    }
    return __real_wioAdd(io, callback, events);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes, void *(*routine)(void *), void *context)
{
    discard thread;
    discard attributes;
    discard routine;
    discard context;
    ++fixture.thread_calls;
    return EAGAIN;
}

bool __wrap_requestProgramShutdown(int code)
{
    require(code != 0, "reader failure requested successful shutdown");
    ++fixture.shutdown_calls;
    return true;
}

_Noreturn void __wrap_abortProgramNow(int code)
{
    fprintf(stderr, "FAIL: capture reader aborted with %d\n", code);
    _Exit(77);
}

void __wrap_memoryFree(void *pointer)
{
    if (pointer != NULL && pointer == fixture.tracked_generation)
        ++fixture.generation_frees;
    if (pointer != NULL && pointer == fixture.tracked_session)
        ++fixture.session_frees;
    __real_memoryFree(pointer);
}

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    require(wid < kWorkers && callback != NULL && cleanup != NULL, "reader message omitted owner or settlement");
    if (fixture.reject_post != 0 && --fixture.reject_post == 0)
    {
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelQuiesced);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    require(fixture.message_count < kMessages, "fixture message inventory overflow");
    fixture.messages[fixture.message_count++] =
        (captured_message_t) {.wid = wid, .callback = callback, .cleanup = cleanup, .args = {arg1, arg2, arg3}};
    return kWorkerMessageSubmitAccepted;
}

static void invokeMessage(void *context)
{
    captured_message_t *message = context;
    message->callback(getCurrentWorker(), message->args[0], message->args[1], message->args[2]);
}

static void runMessage(unsigned index)
{
    require(index < fixture.message_count && ! fixture.messages[index].settled, "message already settled or missing");
    captured_message_t message      = fixture.messages[index];
    fixture.messages[index].settled = true;
    testWorkerBindWID(message.wid);
    require(wloopInvokeNormalCallback(fixture.loops[message.wid], invokeMessage, &message),
            "callback admission failed");
    testWorkerBindWID(0);
}

static void runMessages(void)
{
    for (unsigned i = 0; i < fixture.message_count; ++i)
        if (! fixture.messages[i].settled)
            runMessage(i);
}

static void cancelMessages(void)
{
    testWorkerUnbindWID();
    for (unsigned i = 0; i < fixture.message_count; ++i)
    {
        captured_message_t *message = &fixture.messages[i];
        if (! message->settled)
        {
            message->settled = true;
            message->cleanup(message->args[0], message->args[1], message->args[2], kWorkerMessageCancelTeardown);
        }
    }
    testWorkerBindWID(0);
}

static void runReady(unsigned wid)
{
    testWorkerBindWID((wid_t) wid);
    require(wloopRun(fixture.loops[wid]) >= 0, "real readiness loop failed");
    testWorkerBindWID(0);
}

static void deliverPacket(void *device, sbuf_t *buffer, wid_t wid)
{
    discard device;
    require(currentThreadOwnsWorker(wid), "delivery changed packet owner");
    require(sbufGetLeftCapacity(buffer) >= fixture.required_padding, "capture lost reserved chain padding");
    const uint32_t id = GET_BE16((const uint8_t *) sbufGetRawPtr(buffer) + 4);
    require(id > 0 && id < kPacketIds && fixture.verdicts[id] == NF_DROP, "packet published before successful DROP");
    require(sbufGetLength(buffer) == fixture.packet_lengths[id], "delivery changed packet geometry");
    fixture.delivery_ids[wid][fixture.deliveries[wid]] = id;
    ++fixture.deliveries[wid];
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buffer);
}

static void fixtureSetup(void)
{
    memoryZero(&fixture, sizeof(fixture));
    fixture.command_release_fd = -1;
    for (unsigned i = 0; i < kWorkers; ++i)
        fixture.queues[i].fd = fixture.queues[i].peer = -1;
    for (unsigned i = 0; i < kPacketIds; ++i)
        fixture.verdicts[i] = UINT32_MAX;
    fixture.large                         = masterpoolCreateWithCapacity(16);
    fixture.medium                        = masterpoolCreateWithCapacity(16);
    fixture.small                         = masterpoolCreateWithCapacity(16);
    fixture.wio_master                    = masterpoolCreateWithCapacity(16);
    GSTATE.masterpool_buffer_pools_large  = fixture.large;
    GSTATE.masterpool_buffer_pools_medium = fixture.medium;
    GSTATE.masterpool_buffer_pools_small  = fixture.small;
    GSTATE.workers_count                  = kWorkers;
    atomicStoreRelaxed(&GSTATE.workers_run_flag, true);
    GSTATE.ram_profile = 1;
    testWorkerRegistryInstall(&fixture.registry);
    GSTATE.shortcut_buffer_pools = fixture.pools;
    GSTATE.shortcut_loops        = fixture.loops;
    GSTATE.shortcut_wios_pools   = fixture.wio_pools;
    for (wid_t wid = 0; wid < kWorkers; ++wid)
    {
        testWorkerBindWID(wid);
        fixture.pools[wid] = bufferpoolCreate(
            fixture.large, fixture.medium, fixture.small, 16, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 4096, 8192, 8192);
        fixture.loops[wid] = wloopCreate(WLOOP_FLAG_RUN_ONCE, fixture.pools[wid], wid);
        require(fixture.loops[wid] != NULL, "could not create worker loop");
        GSTATE.workers[wid].buffer_pool = fixture.pools[wid];
        GSTATE.workers[wid].loop        = fixture.loops[wid];
        fixture.wio_pools[wid] =
            threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(fixture.wio_master, sizeof(wio_t), 8);
        GSTATE.workers[wid].wios_pool = fixture.wio_pools[wid];
    }
    testWorkerBindWID(0);
}

static void fixtureTeardown(void)
{
    cancelMessages();
    require(fixture.thread_calls == 0, "capture created an auxiliary reader thread");
    for (wid_t wid = 0; wid < kWorkers; ++wid)
    {
        testWorkerBindWID(wid);
        wloopDestroy(&fixture.loops[wid]);
        threadsafegenericpoolDestroy(fixture.wio_pools[wid]);
        bufferpoolDestroy(fixture.pools[wid]);
        if (fixture.queues[wid].peer >= 0)
            close(fixture.queues[wid].peer);
    }
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&fixture.registry);
    GSTATE.workers_count = 0;
    atomicStoreRelaxed(&GSTATE.workers_run_flag, false);
    GSTATE.shortcut_buffer_pools          = NULL;
    GSTATE.shortcut_loops                 = NULL;
    GSTATE.shortcut_wios_pools            = NULL;
    GSTATE.masterpool_buffer_pools_large  = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;
    GSTATE.masterpool_buffer_pools_small  = NULL;
    masterpoolMakeEmpty(fixture.large);
    masterpoolDestroy(fixture.large);
    masterpoolMakeEmpty(fixture.medium);
    masterpoolDestroy(fixture.medium);
    masterpoolMakeEmpty(fixture.small);
    masterpoolDestroy(fixture.small);
    masterpoolMakeEmpty(fixture.wio_master);
    masterpoolDestroy(fixture.wio_master);
}

static capture_device_t *createReaderAt(unsigned first_queue, unsigned queues, unsigned packet_budget,
                                        device_opaque_flow_mode_t mode)
{
    require(first_queue + queues <= kWorkers, "reader fixture queue inventory exceeded");
    capture_device_t *device   = memoryAllocateZero(sizeof(*device));
    device->name               = stringDuplicate("capture-reader-test");
    device->queue_count        = (uint16_t) queues;
    device->queues             = memoryAllocateZero(queues * sizeof(*device->queues));
    device->queue_restartable  = true;
    device->reader_buffer_pool = devicePoolCreate(getCurrentWorkerBufferPool(), 4096);
    require(device->reader_buffer_pool != NULL, "reader pool creation failed");
    /* Mirror BringUp's finalized geometry before captureReaderOpen sizes the
     * prepared receive storage. This fixture bypasses public BringUp. */
    devicePoolUpdatePadding(device->reader_buffer_pool, getCurrentWorkerBufferPool());
    device->reader_session =
        deviceReaderSessionCreate(16, 1, device, deliverPacket, device->reader_buffer_pool, kDeviceFragmentPreserve);
    require(device->reader_session != NULL, "reader session creation failed");
    deviceFragAffinityEnableShared(device->reader_session->frag_affinity, 0);
    require(
        deviceReaderSessionConfigureOutputBudget(device->reader_session, kCaptureReaderChargeLimit, packet_budget) &&
            deviceReaderSessionEnableWorkerQueue(device->reader_session),
        "reader budget configuration failed");
    deviceReaderSessionConfigureCapacityNotify(device->reader_session, captureReaderCapacityReady, device);
    for (unsigned i = 0; i < queues; ++i)
    {
        int pair[2];
        require(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0,
                "queue socketpair failed");
        const int socket_capacity = 1024 * 1024;
        require(setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &socket_capacity, sizeof(socket_capacity)) == 0,
                "could not enlarge fixture injection capacity");
        fixture.queues[first_queue + i].fd = device->queues[i].fd = pair[0];
        fixture.queues[first_queue + i].peer                      = pair[1];
        fixture.queues[first_queue + i].owner                     = (wid_t) i;
        device->queues[i].number                                  = kFirstQueue + first_queue + i;
    }
    deviceReaderSessionSetOpaqueFlowMode(device->reader_session, mode);
    atomicStoreRelaxed(&device->lifecycle, kCaptureLifecycleStarting);
    require(deviceReaderSessionBegin(device->reader_session) != 0, "reader session open failed");
    captureReaderOpen(device);
    return device;
}

static capture_device_t *createReader(unsigned queues, unsigned packet_budget)
{
    return createReaderAt(0, queues, packet_budget, kDeviceOpaqueFlowPrefix);
}

static bool startReader(capture_device_t *device)
{
    atomicStoreRelaxed(&device->lifecycle, kCaptureLifecycleUp);
    atomicStoreRelaxed(&device->capture_active, true);
    atomicStoreRelaxed(&device->up, true);
    return captureReaderStart(device);
}

static void stopReader(capture_device_t *device)
{
    require(capturedeviceRequestStop(device), "stop request failed");
    for (wid_t wid = 0; wid < kWorkers; ++wid)
    {
        testWorkerBindWID(wid);
        capturedeviceWorkerQuiesce(device, wid);
    }
    testWorkerBindWID(0);
    deviceReaderSessionEndWait(device->reader_session);
    captureReaderCloseWait(device);
    for (unsigned i = 0; i < device->queue_count; ++i)
        require(! wioExists(fixture.loops[i], device->queues[i].fd) && fcntl(device->queues[i].fd, F_GETFD) >= 0,
                "worker detachment closed or retained its native queue");
}

static void destroyReader(capture_device_t *device)
{
    stopReader(device);
    captureReaderDestroy(device);
    deviceReaderSessionRetireProducerBuffers(device->reader_session);
    bufferpoolDestroy(device->reader_buffer_pool);
    deviceReaderSessionUnref(device->reader_session);
    for (unsigned i = 0; i < device->queue_count; ++i)
    {
        const int index = queueIndex(device->queues[i].fd);
        require(index >= 0, "destroyed reader lost its queue inventory");
        close(device->queues[i].fd);
        fixture.queues[index].fd = -1;
    }
    memoryFree(device->queues);
    memoryFree(device->name);
    memoryFree(device);
}

static void sendPacketSized(unsigned queue, unsigned id, wid_t destination, uint8_t protocol, unsigned packet_length,
                            bool malformed)
{
    require(packet_length >= 28 && packet_length <= 8192 && id > 0 && id < kPacketIds,
            "injected packet exceeded fixture geometry");
    fixture.packet_lengths[id] = packet_length;
    uint8_t packet[8192]       = {0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17};
    PUT_BE16(packet + 2, packet_length);
    PUT_BE16(packet + 4, id);
    PUT_BE32(packet + 12, UINT32_C(0x0a000001));
    PUT_BE32(packet + 16, UINT32_C(0x0a000002));
    PUT_BE16(packet + 22, 443);
    PUT_BE16(packet + 24, packet_length - 20);
    packet[9]      = protocol == IPPROTO_TCP ? IPPROTO_TCP : IPPROTO_UDP;
    wid_t selected = kWorkers;
    for (unsigned port = 1; port < 65536; ++port)
    {
        PUT_BE16(packet + 20, port);
        require(deviceFlowAffineWID(packet, packet_length, &selected), "flow hashing rejected the packet");
        if (selected == destination)
            break;
    }
    require(selected == destination, "could not choose the target processing worker");
    packet[9] = protocol;
    if (malformed)
        packet[0] = 0x40;
    _Alignas(ww_max_align_t) uint8_t message[8320] = {0};
    struct nlmsghdr                 *header        = (struct nlmsghdr *) message;
    header->nlmsg_type                             = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET;
    struct nfgenmsg *generic                       = NLMSG_DATA(header);
    generic->version                               = NFNETLINK_V0;
    const size_t   base                            = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(*generic)));
    struct nfattr *attribute                       = (struct nfattr *) (void *) (message + base);
    attribute->nfa_type                            = NFQA_PACKET_HDR;
    attribute->nfa_len                             = NFA_LENGTH(sizeof(struct nfqnl_msg_packet_hdr));
    struct nfqnl_msg_packet_hdr *packet_header     = NFA_DATA(attribute);
    packet_header->packet_id                       = htonl(id);
    packet_header->hw_protocol                     = htons(0x0800);
    const size_t offset                            = base + NFA_ALIGN(attribute->nfa_len);
    attribute                                      = (struct nfattr *) (void *) (message + offset);
    attribute->nfa_type                            = NFQA_PAYLOAD;
    attribute->nfa_len                             = NFA_LENGTH(packet_length);
    memoryCopy(NFA_DATA(attribute), packet, packet_length);
    header->nlmsg_len = offset + NFA_ALIGN(attribute->nfa_len);
    require(send(fixture.queues[queue].peer, message, header->nlmsg_len, MSG_DONTWAIT) == (ssize_t) header->nlmsg_len,
            "could not inject queue packet");
    queue_probe_t *probe = &fixture.queues[queue];
    require(probe->injected_packets < kPacketIds, "fixture packet inventory overflowed");
    probe->packet_ids[probe->injected_packets++] = id;
}

static void sendPacketProtocol(unsigned queue, unsigned id, wid_t destination, uint8_t protocol)
{
    sendPacketSized(queue, id, destination, protocol, 28, false);
}

static void sendPacket(unsigned queue, unsigned id, wid_t destination)
{
    sendPacketProtocol(queue, id, destination, IPPROTO_UDP);
}

static void testReceiveProcessing(unsigned queues)
{
    fixtureSetup();
    capture_device_t *device = createReaderAt(0, queues, 512, kDeviceOpaqueFlowSpread);
    require(startReader(device), "opaque reader startup failed");
    runMessages();
    const uint8_t protocols[] = {1, 6, 17, 49, 50, 132};
    unsigned      id          = 0;
    for (unsigned protocol = 0; protocol < sizeof(protocols); ++protocol)
    {
        unsigned before[kWorkers];
        memoryCopy(before, fixture.deliveries, sizeof(before));
        for (unsigned number = 0; number < 8; ++number)
        {
            const unsigned queue = number % queues;
            sendPacketProtocol(queue, ++id, 0, protocols[protocol]);
            runReady(queue);
            runMessages();
            if (queues > 1)
                require(fixture.deliveries[queue] == before[queue] + number / queues + 1,
                        "opaque packet left its receiving worker for coarse processing affinity");
        }
        const bool native = protocols[protocol] == IPPROTO_TCP || protocols[protocol] == IPPROTO_UDP;
        for (unsigned worker = 0; worker < kWorkers; ++worker)
        {
            const unsigned expected = queues == 1 && native ? (worker == 0 ? 8 : 0) : 8 / kWorkers;
            require(fixture.deliveries[worker] - before[worker] == expected,
                    "reader lost native flow locality or opaque parallel distribution");
        }
    }
    destroyReader(device);
    fixtureTeardown();
}

static void testNativeSingleReaderFlowDistribution(void)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 512);
    require(startReader(device), "native single-reader startup failed");
    runMessages();
    unsigned expected[kWorkers] = {0};
    for (unsigned packet = 0; packet < 8; ++packet)
    {
        const wid_t target = (wid_t) ((packet / 2) % kWorkers);
        sendPacket(0, packet + 1, target);
        runReady(0);
        runMessages();
        ++expected[target];
        for (unsigned worker = 0; worker < kWorkers; ++worker)
            require(fixture.deliveries[worker] == expected[worker],
                    "one native flow changed worker or different ports lost parallel processing");
    }
    destroyReader(device);
    fixtureTeardown();
}

static void testWorkerQueues(void)
{
    for (unsigned queues = 1; queues <= kWorkers; ++queues)
    {
        fixtureSetup();
        capture_device_t *device = createReader(queues, 512);
        require(startReader(device), "worker reader activation failed");
        require(fixture.message_count == queues, "queue activation count differs from receive owners");
        runMessages();
        for (unsigned i = 0; i < queues; ++i)
        {
            const wid_t destination = (wid_t) ((i + 1) % kWorkers);
            sendPacket(i, i + 1, destination);
            runReady(i);
        }
        runMessages();
        require(fixture.deliveries[0] == queues - 1 && fixture.deliveries[1] == 1,
                "capture lost native single-reader locality or changed native multiqueue placement");
        require(queues > 1 || fixture.queues[1].reads == 0, "fallback read from a second worker");
        destroyReader(device);
        fixtureTeardown();
    }
}

static void testBoundedReadiness(void)
{
    fixtureSetup();
    capture_device_t *device  = createReader(1, 512);
    const unsigned    packets = 300;
    for (unsigned id = 1; id <= packets; ++id)
        sendPacket(0, id, 0);
    require(startReader(device), "bounded reader activation failed");
    runMessage(0);
    require(fixture.queues[0].read_packets > 0 && fixture.queues[0].read_packets <= 256,
            "one receive root drained the entire unbounded input");
    require(fixture.deliveries[0] > 0 && fixture.deliveries[0] <= 256, "bounded read root did not yield delivery");
    runReady(0);
    runMessages();
    require(fixture.deliveries[0] == packets && fixture.deliveries[1] == 0,
            "level-triggered readiness lost input or split one visible flow across workers");
    for (unsigned i = 0; i < packets; ++i)
        require(fixture.delivery_ids[0][i] == i + 1, "bounded receive continuation reordered one flow");
    destroyReader(device);
    fixtureTeardown();
}

static void testShortReceiveBatch(void)
{
    fixtureSetup();
    fixture.required_padding = 128;
    globalstateUpdateAllocationPadding(fixture.required_padding);
    capture_device_t *device  = createReader(1, 512);
    const unsigned    packets = 19;
    for (unsigned id = 1; id <= packets; ++id)
        sendPacket(0, id, 0);
    require(startReader(device), "short batch reader activation failed");
    runMessage(0);
    require(fixture.deliveries[0] == packets && fixture.deliveries[1] == 0,
            "short receive batch waited for more packets or lost local delivery");
    require(fixture.queues[0].largest_read == packets && fixture.queues[0].largest_verdict_batch == packets &&
                fixture.queues[0].verdict_batches == 1,
            "available packets did not share receive and explicit-verdict syscalls");
    for (unsigned i = 0; i < packets; ++i)
        require(fixture.delivery_ids[0][i] == i + 1, "short receive batch changed packet order");
    destroyReader(device);
    fixtureTeardown();
}

static void testByteBoundedReadiness(void)
{
    fixtureSetup();
    capture_device_t *device  = createReader(1, 512);
    const unsigned    packets = 180;
    const unsigned    length  = 1500;
    for (unsigned id = 1; id <= packets; ++id)
        sendPacketSized(0, id, 0, IPPROTO_UDP, length, false);
    require(startReader(device), "byte-bounded reader activation failed");
    runMessage(0);
    require(fixture.deliveries[0] > 0 && fixture.deliveries[0] < packets &&
                fixture.deliveries[0] * length < 256U * 1024U + length,
            "large native batch ignored its per-callback byte budget");
    runMessages();
    require(fixture.deliveries[0] == packets && fixture.shutdown_calls == 0,
            "byte-budget continuation stranded an already received batch without another readiness edge");
    for (unsigned i = 0; i < packets; ++i)
        require(fixture.delivery_ids[0][i] == i + 1, "byte-budget continuation reordered retained input");
    destroyReader(device);
    fixtureTeardown();
}

static void testPartialVerdictBatch(bool stopping, bool cumulative_suffix)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 512);
    queue_probe_t    *queue  = &fixture.queues[0];
    queue->send_steps[0]     = 2;
    queue->send_steps[1]     = -EAGAIN;
    queue->send_step_count   = 2;
    for (unsigned id = 1; id <= 6; ++id)
        sendPacket(0, id, 0);
    require(startReader(device), "partial verdict reader activation failed");
    runMessage(0);
    require(queue->read_packets == 6 && queue->verdicts == 2 && fixture.deliveries[0] == 2 &&
                queue->io->events == WW_WRITE,
            "partial verdict completion published its unsent suffix or lost writable interest");
    for (unsigned id = 3; id <= 6; ++id)
        require(fixture.verdicts[id] == UINT32_MAX, "unsent verdict suffix was marked committed");
    device->queues[0].batch_verdicts = cumulative_suffix;
    if (stopping)
    {
        stopReader(device);
        fixture.coordinator = true;
        captureReaderService(device);
        fixture.coordinator = false;
        require(fixture.deliveries[0] == 2, "stop published an unsent DROP suffix");
    }
    else
    {
        runReady(0);
        require(fixture.deliveries[0] == 6, "writable resume did not publish the complete retained suffix");
        for (unsigned i = 0; i < 6; ++i)
            require(fixture.delivery_ids[0][i] == i + 1, "partial verdict completion reordered packet delivery");
    }
    for (unsigned id = 1; id <= 6; ++id)
        require(fixture.verdicts[id] == (stopping && id > 2 ? NF_ACCEPT : NF_DROP),
                "verdict retry changed a committed prefix or mishandled the unsent suffix");
    require(queue->cumulative_attempts == (cumulative_suffix ? 1U : 0U),
            "retained verdict suffix did not use the selected explicit or cumulative path");
    require(fixture.shutdown_calls == 0, "partial verdict completion requested shutdown");
    destroyReader(device);
    fixtureTeardown();
}

static void testPartialVerdictCapacityResume(void)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 1);
    queue_probe_t    *queue  = &fixture.queues[0];
    require(startReader(device), "partial-capacity reader activation failed");
    runMessages();
    queue->send_steps[0]   = 2;
    queue->send_step_count = 1;
    const unsigned packets = 12;
    for (unsigned id = 1; id <= packets; ++id)
        sendPacket(0, id, 1);
    runReady(0);
    const uint32_t timers = wloopNTimers(fixture.loops[0]);
    require(queue->read_packets == packets && queue->io->events == 0 && fixture.deliveries[1] == 0 &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
            "partial-capacity fixture did not retain a full destination FIFO");

    /* Delay only the foreign destination's queued delivery beyond the native
     * verdict deadline. FIFO pressure must not prevent a writable verdict. */
    usleep(300000);
    if (queue->verdicts < packets)
        runReady(0);
    runMessages();
    require(fixture.shutdown_calls == 0 && fixture.deliveries[1] == packets &&
                captureLifecycleLoad(&device->lifecycle) == kCaptureLifecycleUp && queue->verdicts == packets &&
                queue->io->events == WW_READ && wloopNTimers(fixture.loops[0]) == timers &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 0,
            "partial verdicts expired behind FIFO pressure or lost ordered capacity recovery");
    for (unsigned i = 0; i < packets; ++i)
        require(fixture.delivery_ids[1][i] == i + 1 && fixture.verdicts[i + 1] == NF_DROP,
                "partial-capacity recovery reordered input or changed a committed verdict");
    destroyReader(device);
    fixtureTeardown();
}

static void testPendingVerdictWithFullFifo(bool stopping, bool deadline)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 1);
    queue_probe_t    *queue  = &fixture.queues[0];
    require(startReader(device), "full-FIFO verdict reader activation failed");
    runMessages();
    sendPacket(0, 1, 1);
    runReady(0);
    const uint32_t timers = wloopNTimers(fixture.loops[0]);
    require(fixture.verdicts[1] == NF_DROP && fixture.deliveries[1] == 0 && queue->io->events == WW_READ &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
            "full-FIFO verdict fixture did not retain its first admitted packet");
    queue->send_steps[0]   = 2;
    queue->send_steps[1]   = -EAGAIN;
    queue->send_step_count = 2;
    for (unsigned id = 2; id <= 7; ++id)
        sendPacket(0, id, 1);
    runReady(0);
    const unsigned reads = queue->reads;
    require(queue->verdicts == 3 && queue->io->events == WW_WRITE && fixture.deliveries[1] == 0 &&
                wloopNTimers(fixture.loops[0]) == timers + 1 &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
            "full destination FIFO suppressed pending-verdict writable readiness or its deadline");
    for (unsigned id = 4; id <= 7; ++id)
        require(fixture.verdicts[id] == UINT32_MAX, "blocked verdict suffix was marked committed");
    if (stopping)
    {
        stopReader(device);
        fixture.coordinator = true;
        captureReaderService(device);
        fixture.coordinator = false;
        runMessages();
        require(queue->verdicts == 7 && fixture.deliveries[1] == 0 && fixture.shutdown_calls == 0 &&
                    wloopNTimers(fixture.loops[0]) == timers &&
                    atomicLoadRelaxed(&device->reader_session->output_packets) == 0,
                "stopped full-FIFO verdict batch published input, leaked credits or retained its verdict timer");
        for (unsigned id = 1; id <= 7; ++id)
            require(fixture.verdicts[id] == (id <= 3 ? NF_DROP : NF_ACCEPT),
                    "stop changed a committed prefix or failed to accept only the unsent suffix");
    }
    else if (deadline)
    {
        queue->verdict_error = EAGAIN;
        usleep(300000);
        runReady(0);
        runMessages();
        require(captureLifecycleLoad(&device->lifecycle) == kCaptureLifecycleFailed && fixture.shutdown_calls == 1 &&
                    queue->verdicts == 3 && queue->reads == reads && queue->io->events == 0 &&
                    fixture.deliveries[1] == 0 && atomicLoadRelaxed(&device->reader_session->output_packets) == 0,
                "FIFO pressure bypassed the actual verdict deadline or admitted publication after its failure");
        for (unsigned id = 4; id <= 7; ++id)
            require(fixture.verdicts[id] == UINT32_MAX, "expired verdict was marked committed");
    }
    else
    {
        runReady(0);
        require(queue->verdicts == 7 && queue->reads == reads && queue->io->events == 0 && fixture.deliveries[1] == 0 &&
                    wloopNTimers(fixture.loops[0]) == timers &&
                    atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
                "writable retry did not settle pending verdicts independently of the full destination FIFO");
        runMessages();
        require(fixture.deliveries[1] == 7 && fixture.shutdown_calls == 0 && queue->io->events == WW_READ &&
                    atomicLoadRelaxed(&device->reader_session->output_packets) == 0,
                "full-FIFO verdict recovery lost packets, credits or read interest");
        for (unsigned i = 0; i < 7; ++i)
            require(fixture.delivery_ids[1][i] == i + 1 && fixture.verdicts[i + 1] == NF_DROP,
                    "full-FIFO verdict recovery reordered packets or changed their ownership");
    }
    destroyReader(device);
    fixtureTeardown();
}

static void testInterruptedBatch(bool receive, bool stopping)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 512);
    queue_probe_t    *queue  = &fixture.queues[0];
    if (receive)
    {
        queue->read_error  = EINTR;
        queue->read_errors = kCaptureInterruptedRetryBudget;
    }
    else
        queue->verdict_error = EINTR;
    for (unsigned id = 1; id <= 6; ++id)
        sendPacket(0, id, 0);
    require(startReader(device), "interrupted reader activation failed");
    runMessage(0);
    require(fixture.deliveries[0] == 0 && fixture.message_count == 2 &&
                (receive ? queue->reads : queue->verdict_attempts) == kCaptureInterruptedRetryBudget,
            "interrupted batch did not yield within its retry bound and retain an explicit continuation");
    queue->read_errors   = 0;
    queue->verdict_error = 0;
    if (stopping)
    {
        stopReader(device);
        fixture.coordinator = true;
        captureReaderService(device);
        fixture.coordinator = false;
        require(fixture.deliveries[0] == 0, "interrupted stop published retained capture packets");
    }
    else
    {
        runMessages();
        require(fixture.deliveries[0] == 6, "interrupted batch continuation lost input");
    }
    for (unsigned id = 1; id <= 6; ++id)
        require(fixture.verdicts[id] == (stopping ? NF_ACCEPT : NF_DROP),
                "interrupted batch continuation changed verdict ownership");
    require(fixture.shutdown_calls == 0, "interrupted batch requested shutdown");
    destroyReader(device);
    fixtureTeardown();
}

static void testMixedReceiveBatch(bool cumulative)
{
    fixtureSetup();
    capture_device_t *device         = createReader(1, 512);
    device->queues[0].batch_verdicts = cumulative;
    sendPacket(0, 1, 0);
    sendPacketSized(0, 2, 0, IPPROTO_UDP, 28, true);
    sendPacketSized(0, 3, 0, IPPROTO_UDP, 8192, false);
    sendPacket(0, 4, 0);
    require(startReader(device), "mixed batch reader activation failed");
    runMessage(0);
    require(fixture.queues[0].largest_read == 4 && fixture.queues[0].verdicts == 4 && fixture.deliveries[0] == 2 &&
                fixture.delivery_ids[0][0] == 1 && fixture.delivery_ids[0][1] == 4,
            "malformed or truncated middle record lost valid neighbors or was published");
    for (unsigned id = 1; id <= 4; ++id)
        require(fixture.verdicts[id] == NF_DROP, "discarded batch input lost its own verdict");
    require(fixture.shutdown_calls == 0, "recoverable malformed batch input failed capture");
    destroyReader(device);
    fixtureTeardown();
}

static void invokeStoredReady(void *context)
{
    queue_probe_t *queue = context;
    require(queue->io != NULL && queue->callback != NULL, "reader omitted its installed readiness callback");
    queue->callback(queue->io);
}

static void testUnrecoverableReceiveBatch(void)
{
    fixtureSetup();
    capture_device_t *device         = createReader(1, 512);
    queue_probe_t    *queue          = &fixture.queues[0];
    device->queues[0].batch_verdicts = true;
    fixture.tracked_generation       = device->reader;
    fixture.tracked_session          = device->reader_session;
    require(startReader(device), "unrecoverable receive reader activation failed");
    runMessages();
    sendPacket(0, 1, 1);
    sendPacket(0, 2, 1);
    const uint8_t invalid_envelope = 0;
    require(send(queue->peer, &invalid_envelope, sizeof(invalid_envelope), MSG_DONTWAIT) ==
                (ssize_t) sizeof(invalid_envelope),
            "could not inject an envelope without a readable packet ID");
    sendPacket(0, 3, 1);
    sendPacket(0, 4, 1);
    const unsigned reads = queue->reads;
    runReady(0);
    require(queue->largest_read == 5 && queue->reads == reads + 1 && queue->verdicts == 4 &&
                queue->verdict_batches == 2 && queue->largest_verdict_batch == 2 && queue->cumulative_attempts == 0,
            "unrecoverable envelope lost known packet verdicts, used cumulative settlement or read another batch");
    for (unsigned id = 1; id <= 4; ++id)
        require(fixture.verdicts[id] == NF_DROP, "unrecoverable batch left a known packet without its own verdict");
    require(captureLifecycleLoad(&device->lifecycle) == kCaptureLifecycleFailed && fixture.shutdown_calls == 1 &&
                ! capturedeviceIsUp(device) && queue->io->events == 0,
            "unrecoverable envelope did not fail capture once and disable native readiness");
    runMessages();
    require(fixture.deliveries[0] == 0 && fixture.deliveries[1] == 0 &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 0,
            "unrecoverable batch admitted delayed publication or retained FIFO credits after failure");
    sendPacket(0, 5, 1);
    for (unsigned i = 0; i < 2; ++i)
        require(wloopInvokeNormalCallback(fixture.loops[0], invokeStoredReady, queue),
                "failed-reader callback admission failed");
    require(queue->reads == reads + 1 && fixture.verdicts[5] == UINT32_MAX && fixture.shutdown_calls == 1 &&
                fixture.deliveries[0] == 0 && fixture.deliveries[1] == 0,
            "failed capture read new native input, published a packet or requested shutdown again");
    destroyReader(device);
    cancelMessages();
    require(fixture.generation_frees == 1 && fixture.session_frees == 1,
            "unrecoverable native batch retained its generation or session after destruction and settlement");
    fixtureTeardown();
}

static void testCumulativeVerdictBatch(bool stopping)
{
    fixtureSetup();
    capture_device_t *device         = createReader(1, 512);
    queue_probe_t    *queue          = &fixture.queues[0];
    device->queues[0].batch_verdicts = true;
    queue->verdict_error             = stopping ? EAGAIN : 0;
    const unsigned ids[]             = {5, 6, 7, 8};
    for (unsigned i = 0; i < ARRAY_SIZE(ids); ++i)
        sendPacket(0, ids[i], 0);
    require(startReader(device), "cumulative verdict reader activation failed");
    runMessage(0);
    if (stopping)
    {
        require(queue->cumulative_attempts == 1 && queue->verdicts == 0 && fixture.deliveries[0] == 0 &&
                    queue->io->events == WW_WRITE,
                "blocked cumulative DROP published input or lost its pending prefix");
        queue->verdict_error = 0;
        stopReader(device);
        fixture.coordinator = true;
        captureReaderService(device);
        fixture.coordinator = false;
        require(fixture.deliveries[0] == 0 && queue->cumulative_attempts == 2,
                "stopped cumulative prefix was published or lost its ACCEPT retry");
    }
    else
    {
        require(fixture.deliveries[0] == ARRAY_SIZE(ids) && queue->cumulative_attempts == 1,
                "cumulative verdict did not settle all packets with one message");
        for (unsigned i = 0; i < ARRAY_SIZE(ids); ++i)
            require(fixture.delivery_ids[0][i] == ids[i], "cumulative verdict changed packet order");
    }
    require(queue->cumulative_boundary == ids[ARRAY_SIZE(ids) - 1] && queue->verdict_batches == 0 &&
                queue->verdicts == ARRAY_SIZE(ids),
            "cumulative verdict did not use the last received packet ID as its exact prefix boundary");
    for (unsigned i = 0; i < ARRAY_SIZE(ids); ++i)
        require(fixture.verdicts[ids[i]] == (stopping ? NF_ACCEPT : NF_DROP),
                "cumulative verdict changed packet ownership");
    require(fixture.verdicts[9] == UINT32_MAX && fixture.verdicts[10] == UINT32_MAX,
            "cumulative verdict fabricated missing packet IDs");
    if (! stopping)
    {
        sendPacket(0, 12, 0);
        sendPacket(0, 13, 0);
        runReady(0);
        require(queue->cumulative_attempts == 2 && queue->cumulative_boundary == 13 && queue->verdicts == 6 &&
                    fixture.deliveries[0] == 6 && fixture.delivery_ids[0][4] == 12 && fixture.delivery_ids[0][5] == 13,
                "later cumulative prefix repeated an old verdict or lost new packets");
    }
    require(fixture.shutdown_calls == 0, "normal cumulative verdict processing requested shutdown");
    destroyReader(device);
    fixtureTeardown();
}

static void testSparseVerdictBatch(void)
{
    fixtureSetup();
    capture_device_t *device         = createReader(1, 512);
    queue_probe_t    *queue          = &fixture.queues[0];
    device->queues[0].batch_verdicts = true;
    const unsigned ids[]             = {5, 8, 11, 17};
    for (unsigned i = 0; i < ARRAY_SIZE(ids); ++i)
        sendPacket(0, ids[i], 0);
    require(startReader(device), "sparse verdict reader activation failed");
    runMessage(0);
    require(queue->cumulative_attempts == 0 && queue->verdict_batches == 1 &&
                queue->largest_verdict_batch == ARRAY_SIZE(ids) && queue->verdicts == ARRAY_SIZE(ids) &&
                fixture.deliveries[0] == ARRAY_SIZE(ids),
            "nonconsecutive packet IDs did not fall back to one explicit verdict batch");
    for (unsigned i = 0; i < ARRAY_SIZE(ids); ++i)
        require(fixture.verdicts[ids[i]] == NF_DROP && fixture.delivery_ids[0][i] == ids[i],
                "explicit verdict fallback changed packet order or ownership");
    require(fixture.verdicts[6] == UINT32_MAX && fixture.verdicts[9] == UINT32_MAX && fixture.shutdown_calls == 0,
            "explicit verdict fallback fabricated missing IDs or failed capture");
    destroyReader(device);
    fixtureTeardown();
}

static void testCoordinatorScratchRetainsPadding(void)
{
    fixtureSetup();
    fixture.required_padding = 256;
    globalstateUpdateAllocationPadding(fixture.required_padding);
    capture_device_t *device = createReader(1, 512);
    fixture.coordinator      = true;
    captureReaderService(device);
    fixture.coordinator = false;
    require(fixture.queues[0].reads > 0 && fixture.queues[0].verdicts == 0,
            "coordinator did not allocate empty-queue receive scratch before activation");
    sendPacket(0, 1, 0);
    require(startReader(device), "padded reader activation failed");
    runMessages();
    require(fixture.deliveries[0] == 1, "first worker packet did not reuse coordinator scratch for delivery");
    destroyReader(device);
    fixtureTeardown();
}

static void testPreparedStorageBudget(void)
{
    fixtureSetup();
    fixture.required_padding = 32768;
    globalstateUpdateAllocationPadding(fixture.required_padding);
    capture_device_t *device = createReader(kWorkers, 512);
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(device->reader_buffer_pool, kNetfilterReadBufferSize, 0, &fit),
            "could not query padded capture allocation geometry");
    const size_t   allowed_per_queue = kCaptureReaderChargeLimit / (kWorkers * fit.allocation_charge);
    const unsigned packets           = 200;
    require(allowed_per_queue > 0 && allowed_per_queue < packets,
            "large-padding fixture did not exercise prepared-storage capacity reduction");
    for (unsigned queue = 0; queue < kWorkers; ++queue)
        for (unsigned i = 0; i < packets; ++i)
            sendPacket(queue, queue * packets + i + 1, (wid_t) queue);
    require(startReader(device), "padded multiqueue reader activation failed");
    runMessages();
    for (unsigned queue = 0; queue < kWorkers; ++queue)
    {
        const queue_probe_t *probe = &fixture.queues[queue];
        require(probe->largest_receive_request > 0 && probe->largest_receive_request <= allowed_per_queue &&
                    probe->read_batches > 1 && probe->read_packets == packets && fixture.deliveries[queue] == packets,
                "padded multiqueue batch exceeded its shared storage budget or lost later input");
        for (unsigned i = 0; i < packets; ++i)
            require(fixture.delivery_ids[queue][i] == queue * packets + i + 1,
                    "storage-limited batches changed per-queue packet order");
    }
    require(fixture.shutdown_calls == 0, "storage-limited capture requested shutdown");
    destroyReader(device);
    fixtureTeardown();
}

static void testActiveStartupCommandService(bool limited_capacity)
{
    fixtureSetup();
    atomicStoreRelaxed(&GSTATE.workers_run_flag, false);
    capture_device_t *device = createReader(1, limited_capacity ? 1 : 512);
    require(startReader(device), "startup service could not queue worker activation");
    const unsigned packets = limited_capacity ? 3 : 1;
    for (unsigned id = 1; id <= packets; ++id)
        sendPacket(0, id, 1);

    /* Socket-manager startup commands run after Capture is active but before
     * workers are released. Registry service must retain capture semantics and
     * enqueue delivery without invoking the packet chain on the coordinator. */
    const char *const            argv[]  = {"true", NULL};
    const proc_command_options_t options = {.timeout_ms = 1000, .terminate_grace_ms = 100, .max_output_bytes = 64};
    proc_command_result_t        result;
    fixture.coordinator  = true;
    const bool completed = procRunArgvWithDeadline("/bin/true", argv, &options, &result);
    fixture.coordinator  = false;
    require(completed, "startup registry command failed");
    procCommandResultDrop(&result);
    require(fixture.verdicts[1] == NF_DROP && fixture.deliveries[1] == 0 && fixture.queues[0].io == NULL &&
                fixture.message_count == 2 && atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
            "active startup service bypassed capture or delivered before worker activation");
    if (limited_capacity)
        require(fixture.queues[0].read_packets >= 2 && fixture.queues[0].read_packets <= packets &&
                    fixture.verdicts[2] == NF_DROP,
                "startup capacity refusal failed to retain its bounded native input");

    atomicStoreRelaxed(&GSTATE.workers_run_flag, true);
    runMessage(0);
    require(fixture.deliveries[1] == 0, "reader activation bypassed the already queued foreign delivery");
    runMessages();
    require(fixture.deliveries[0] == 0 && fixture.deliveries[1] == packets && fixture.queues[0].io->events == WW_READ &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 0 && fixture.shutdown_calls == 0,
            "worker release failed to deliver startup input and resume retained capacity work");
    for (unsigned id = 1; id <= packets; ++id)
        require(fixture.verdicts[id] == NF_DROP, "startup-to-worker handoff changed a captured packet's verdict");
    destroyReader(device);
    fixtureTeardown();
}

static void testPendingVerdict(bool stopping)
{
    fixtureSetup();
    capture_device_t *device        = createReader(1, 512);
    fixture.queues[0].verdict_error = EAGAIN;
    sendPacket(0, 1, 0);
    require(startReader(device), "verdict reader activation failed");
    runMessage(0);
    require(fixture.queues[0].reads == 1 && fixture.deliveries[0] == 0 && fixture.queues[0].io->events == WW_WRITE,
            "EAGAIN did not retain the record on writable interest");
    fixture.queues[0].verdict_error = 0;
    if (stopping)
    {
        stopReader(device);
        fixture.coordinator = true;
        captureReaderService(device);
        fixture.coordinator = false;
        require(fixture.verdicts[1] == NF_ACCEPT && fixture.deliveries[0] == 0,
                "stop published or dropped a packet whose DROP was still unsent");
    }
    else
    {
        runReady(0);
        require(fixture.verdicts[1] == NF_DROP && fixture.deliveries[0] == 1,
                "writable readiness failed to settle and publish retained input");
    }
    require(fixture.shutdown_calls == 0, "normal verdict backpressure or stop requested shutdown");
    destroyReader(device);
    fixtureTeardown();
}

static void testCapacityResume(void)
{
    fixtureSetup();
    capture_device_t *device  = createReader(1, 1);
    const unsigned    packets = 12;
    for (unsigned id = 1; id <= packets; ++id)
        sendPacket(0, id, 1);
    require(startReader(device), "capacity reader activation failed");
    runMessage(0);
    require(fixture.queues[0].read_packets == packets && fixture.queues[0].io->events == 0 &&
                fixture.message_count == 2 && atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
            "capacity refusal did not disable reads while retaining the native batch");
    const unsigned reads = fixture.queues[0].reads;
    sendPacket(0, packets + 1, 1);
    for (unsigned i = 0; i < 2; ++i)
    {
        const unsigned message = fixture.message_count;
        captureReaderCapacityReady(device);
        require(fixture.message_count == message + 1, "capacity notification did not queue its owner callback");
        runMessage(message);
    }
    require(fixture.queues[0].reads == reads && atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
            "capacity-blocked callbacks consumed more native input or exceeded FIFO credits");
    const unsigned messages = fixture.message_count;
    runMessage(1);
    require(fixture.deliveries[1] == 1 && fixture.message_count == messages + 1 && fixture.messages[messages].wid == 0,
            "foreign worker credit release did not wake the reader owner");
    runMessages();
    require(fixture.deliveries[0] == 0 && fixture.deliveries[1] == packets + 1 &&
                fixture.queues[0].io->events == WW_READ &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 0,
            "capacity wake lost retained input, read interest or credits");
    for (unsigned i = 0; i <= packets; ++i)
        require(fixture.delivery_ids[1][i] == i + 1, "capacity wake reordered native retained input");
    destroyReader(device);
    fixtureTeardown();
}

static void testStopCapacityBatch(void)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 1);
    for (unsigned id = 1; id <= 12; ++id)
        sendPacket(0, id, 1);
    require(startReader(device), "stopped capacity reader activation failed");
    runMessage(0);
    require(fixture.queues[0].verdicts == 12 && fixture.deliveries[1] == 0 &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 1,
            "stopped capacity fixture did not retain committed unpublished packets");
    stopReader(device);
    fixture.coordinator = true;
    captureReaderService(device);
    fixture.coordinator = false;
    runMessages();
    require(fixture.deliveries[0] == 0 && fixture.deliveries[1] == 0 && fixture.queues[0].verdicts == 12 &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 0 && fixture.shutdown_calls == 0,
            "stop republished retained packets, resent committed verdicts or leaked FIFO credits");
    for (unsigned id = 1; id <= 12; ++id)
        require(fixture.verdicts[id] == NF_DROP, "stop changed a previously committed DROP verdict");
    destroyReader(device);
    fixtureTeardown();
}

static void testActivationRefusalAndLateCancel(void)
{
    fixtureSetup();
    capture_device_t *device   = createReader(2, 512);
    fixture.tracked_generation = device->reader;
    fixture.tracked_session    = device->reader_session;
    fixture.reject_post        = 2;
    require(! startReader(device), "partially refused startup reported success");
    require(fixture.message_count == 1, "partial activation lost its accepted callback");
    destroyReader(device);
    require(fixture.generation_frees == 0 && fixture.session_frees == 0, "accepted startup token lost its lifetime");
    cancelMessages();
    require(fixture.generation_frees == 1 && fixture.session_frees == 1 && fixture.shutdown_calls == 0,
            "foreign cancellation did not release the destroyed device's generation exactly once");
    fixtureTeardown();
}

static void testStaleGenerationAfterRestart(void)
{
    fixtureSetup();
    capture_device_t *device   = createReader(1, 512);
    fixture.tracked_generation = device->reader;
    require(startReader(device), "old generation startup failed");
    stopReader(device);
    captureReaderDestroy(device);
    deviceReaderSessionRetireGenerationBuffers(device->reader_session);
    require(fixture.generation_frees == 0, "old queued startup failed to retain the closed generation");
    require(deviceReaderSessionBegin(device->reader_session) != 0, "reader session restart failed");
    captureReaderOpen(device);
    require(startReader(device), "reader restart failed");
    runMessage(0);
    require(fixture.generation_frees == 1 && fixture.queues[0].reads == 0,
            "old startup callback read from the reopened device");
    runMessages();
    sendPacket(0, 1, 0);
    runReady(0);
    require(fixture.deliveries[0] == 1, "new generation failed after stale callback settlement");
    fixture.tracked_generation = NULL;
    destroyReader(device);
    fixtureTeardown();
}

static void testQueuedDeliveryAfterDestroy(bool cancel)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 512);
    fixture.tracked_session  = device->reader_session;
    sendPacket(0, 1, 1);
    require(startReader(device), "delayed-delivery reader startup failed");
    runMessage(0);
    require(fixture.message_count == 2 && fixture.deliveries[1] == 0, "foreign delivery was not queued");
    destroyReader(device);
    require(fixture.session_frees == 0, "queued delivery lost session before settlement");
    if (cancel)
        cancelMessages();
    else
        runMessages();
    require(fixture.session_frees == 1 && fixture.deliveries[1] == 0,
            "late delivery/cancellation touched destroyed device or retained its session");
    fixtureTeardown();
}

static void testWatcherFailure(void)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 512);
    fixture.fail_add         = true;
    sendPacket(0, 2, 1);
    require(startReader(device), "watcher failure fixture could not queue startup");
    runMessage(0);
    require(fixture.verdicts[2] == NF_DROP && fixture.message_count == 2 && fixture.deliveries[1] == 0,
            "watcher failure fixture did not retain an admitted foreign delivery");
    require(captureLifecycleLoad(&device->lifecycle) == kCaptureLifecycleFailed && fixture.shutdown_calls == 1 &&
                ! capturedeviceIsUp(device),
            "failed watcher registration left a live capture device without a reader");
    runMessages();
    require(fixture.deliveries[1] == 0, "watcher failure left queued session delivery open");
    destroyReader(device);
    fixtureTeardown();
}

static void testVerdictFailure(bool deadline)
{
    fixtureSetup();
    capture_device_t *device = createReader(1, 512);
    sendPacket(0, 2, 1);
    require(startReader(device), "verdict failure fixture could not queue startup");
    runMessage(0);
    require(fixture.verdicts[2] == NF_DROP && fixture.message_count == 2 && fixture.deliveries[1] == 0,
            "verdict failure fixture did not retain an admitted foreign delivery");
    fixture.queues[0].verdict_error = deadline ? EAGAIN : EPERM;
    sendPacket(0, 1, 0);
    runReady(0);
    if (deadline)
    {
        // Exercise the actual one-shot deadline after writable backpressure.
        // No timing threshold is measured; elapsed time only makes it due.
        usleep(300000);
        runReady(0);
    }
    require(captureLifecycleLoad(&device->lifecycle) == kCaptureLifecycleFailed && fixture.shutdown_calls == 1 &&
                ! capturedeviceIsUp(device) && fixture.deliveries[0] == 0,
            "failed or expired verdict published the packet or left capture live");
    runMessages();
    require(fixture.deliveries[1] == 0, "verdict failure left queued session delivery open");
    destroyReader(device);
    fixtureTeardown();
}

typedef struct command_service_s
{
    capture_device_t *device;
    unsigned          calls;
    int               release_fd;
} command_service_t;
static void serviceCommandQueues(void *context)
{
    command_service_t *service = context;
    ++service->calls;
    if (service->calls == 3)
        fixture.queues[0].verdict_error = 0;
    captureReaderService(service->device);
    if (service->calls == 3)
    {
        require(fixture.verdicts[1] == NF_ACCEPT && fixture.verdicts[2] == NF_ACCEPT,
                "coordinator failed to accept input from every queue during a quiet command");
        require(write(service->release_fd, "x", 1) == 1, "could not release supervised command");
    }
}

static void testCoordinatorCommandService(void)
{
    fixtureSetup();
    capture_device_t *device = createReader(2, 512);
    sendPacket(0, 1, 0);
    sendPacket(1, 2, 1);
    fixture.queues[0].verdict_error = EAGAIN;
    char      release_path[]        = "/tmp/waterwall-capture-service-XXXXXX";
    const int release_fd            = mkstemp(release_path);
    require(release_fd >= 0, "could not create command release file");
    command_service_t service = {.device = device, .release_fd = release_fd};
    const char *const argv[]  = {"sh", "-c", "while [ ! -s \"$1\" ]; do sleep 0.01; done", "sh", release_path, NULL};
    const proc_command_options_t options = {.timeout_ms         = 5000,
                                            .terminate_grace_ms = 250,
                                            .max_output_bytes   = 64,
                                            .progress           = serviceCommandQueues,
                                            .progress_context   = &service};
    proc_command_result_t        result;
    fixture.coordinator  = true;
    const bool completed = procRunArgvWithDeadline("/bin/sh", argv, &options, &result);
    fixture.coordinator  = false;
    require(completed, "queue-service command failed");
    require(service.calls >= 3 && fixture.deliveries[0] == 0 && fixture.deliveries[1] == 0,
            "inactive command service forwarded normal traffic or failed to recur");
    procCommandResultDrop(&result);
    close(release_fd);
    require(unlink(release_path) == 0, "could not remove command release file");
    destroyReader(device);
    fixtureTeardown();
}

typedef enum coordinator_wait_case_e
{
    kCoordinatorWaitOwnCommand,
    kCoordinatorWaitOtherCommand,
    kCoordinatorWaitScript,
    kCoordinatorWaitResidualDrain
} coordinator_wait_case_t;

static void testOtherDeviceDuringSequentialCleanup(coordinator_wait_case_t wait_case)
{
    fixtureSetup();
    capture_device_t *first  = createReaderAt(0, 1, 512, kDeviceOpaqueFlowPrefix);
    capture_device_t *second = createReaderAt(1, 1, 512, kDeviceOpaqueFlowPrefix);
    require(startReader(first) && startReader(second), "two-device activation failed");
    runMessages();

    /* The application closes every producer and quiesces all workers before
     * visiting component waits one at a time. The second device has not reached
     * EndWait/CloseWait when the first device's cleanup command blocks. */
    require(capturedeviceRequestStop(first) && capturedeviceRequestStop(second), "two-device stop request failed");
    for (wid_t wid = 0; wid < kWorkers; ++wid)
    {
        testWorkerBindWID(wid);
        capturedeviceWorkerQuiesce(first, wid);
        capturedeviceWorkerQuiesce(second, wid);
    }
    testWorkerBindWID(0);
    deviceReaderSessionEndWait(first->reader_session);
    captureReaderCloseWait(first);
    require(! wioExists(fixture.loops[0], first->queues[0].fd) && ! wioExists(fixture.loops[0], second->queues[0].fd),
            "two-device owner quiescence left a native watcher attached");

    sendPacket(0, 1, 0);
    sendPacket(1, 2, 1);
    fixture.coordinator = true;
    if (wait_case == kCoordinatorWaitResidualDrain)
    {
        fixture.queues[0].verdict_error = EAGAIN;
        captureReaderService(first);
        require(fixture.queues[0].verdict_attempts > 0 && fixture.verdicts[1] == UINT32_MAX &&
                    fixture.verdicts[2] == UINT32_MAX,
                "residual drain fixture did not retain A's blocked verdict and B's unread packet");
        /* B's successful ACCEPT makes A writable. A local-only drain expires
         * without ever releasing either packet; registered service settles both. */
        fixture.release_verdict_after_peer = true;
        require(captureReaderDrain(first) && ! fixture.release_verdict_after_peer,
                "residual draining stranded another device until its own verdict timeout");
    }
    else
    {
        char      release_path[] = "/tmp/waterwall-capture-multiple-XXXXXX";
        const int release_fd     = mkstemp(release_path);
        require(release_fd >= 0, "could not create two-device command release file");
        fixture.command_release_fd = release_fd;
        if (wait_case == kCoordinatorWaitScript)
        {
            char command[512];
            /* Bound only the test script, leaving execCmd's ordinary no-timeout
             * contract intact. Success still requires actual queue progress. */
            stringNPrintf(command,
                          sizeof(command),
                          "i=0; while [ ! -s '%s' ] && [ \"$i\" -lt 500 ]; do "
                          "sleep 0.01; i=$((i+1)); done; test -s '%s'",
                          release_path,
                          release_path);
            require(execCmd(command).exit_code == 0, "a pre-down-style script stranded another device's bound queue");
        }
        else
        {
            const char *const argv[] = {
                "sh", "-c", "while [ ! -s \"$1\" ]; do sleep 0.01; done", "sh", release_path, NULL};
            const bool                   own_command = wait_case == kCoordinatorWaitOwnCommand;
            const proc_command_options_t options     = {.timeout_ms         = 5000,
                                                        .terminate_grace_ms = 250,
                                                        .max_output_bytes   = 64,
                                                        .progress           = own_command ? captureReaderService : NULL,
                                                        .progress_context   = own_command ? first : NULL};
            proc_command_result_t        result;
            const bool                   completed = procRunArgvWithDeadline("/bin/sh", argv, &options, &result);
            require(completed, "sequential cleanup stranded another device during a supervised command");
            procCommandResultDrop(&result);
        }
        close(release_fd);
        require(unlink(release_path) == 0, "could not remove two-device command release file");
    }
    fixture.coordinator = false;
    require(fixture.command_release_fd == -1 && fixture.verdicts[1] == NF_ACCEPT && fixture.verdicts[2] == NF_ACCEPT,
            "registered service did not accept packets from both devices before command completion");
    require(fixture.deliveries[0] == 0 && fixture.deliveries[1] == 0 && fixture.shutdown_calls == 0,
            "quiesced multi-device service published a packet or requested shutdown");
    require(fcntl(first->queues[0].fd, F_GETFD) >= 0 && fcntl(second->queues[0].fd, F_GETFD) >= 0,
            "coordinator service closed healthy queues instead of settling their verdicts");
    destroyReader(first);
    destroyReader(second);
    fixtureTeardown();
}

int main(void)
{
    testCaseSet("capture_linux_reader_test");
    testWorkerQueues();
    testNativeSingleReaderFlowDistribution();
    testReceiveProcessing(1);
    testReceiveProcessing(kWorkers);
    testShortReceiveBatch();
    testBoundedReadiness();
    testByteBoundedReadiness();
    testPartialVerdictCapacityResume();
    testPendingVerdictWithFullFifo(false, false);
    testPendingVerdictWithFullFifo(false, true);
    testPendingVerdictWithFullFifo(true, false);
    testPartialVerdictBatch(false, false);
    testPartialVerdictBatch(true, false);
    testPartialVerdictBatch(false, true);
    testPartialVerdictBatch(true, true);
    testInterruptedBatch(true, false);
    testInterruptedBatch(true, true);
    testInterruptedBatch(false, false);
    testInterruptedBatch(false, true);
    testMixedReceiveBatch(false);
    testMixedReceiveBatch(true);
    testUnrecoverableReceiveBatch();
    testCumulativeVerdictBatch(false);
    testCumulativeVerdictBatch(true);
    testSparseVerdictBatch();
    testCoordinatorScratchRetainsPadding();
    testPreparedStorageBudget();
    testActiveStartupCommandService(false);
    testActiveStartupCommandService(true);
    testPendingVerdict(false);
    testPendingVerdict(true);
    testCapacityResume();
    testStopCapacityBatch();
    testActivationRefusalAndLateCancel();
    testStaleGenerationAfterRestart();
    testQueuedDeliveryAfterDestroy(false);
    testQueuedDeliveryAfterDestroy(true);
    testWatcherFailure();
    testVerdictFailure(false);
    testVerdictFailure(true);
    testCoordinatorCommandService();
    testOtherDeviceDuringSequentialCleanup(kCoordinatorWaitOwnCommand);
    testOtherDeviceDuringSequentialCleanup(kCoordinatorWaitOtherCommand);
    testOtherDeviceDuringSequentialCleanup(kCoordinatorWaitScript);
    testOtherDeviceDuringSequentialCleanup(kCoordinatorWaitResidualDrain);
    puts("Linux Capture worker-reader tests passed");
    return 0;
}
