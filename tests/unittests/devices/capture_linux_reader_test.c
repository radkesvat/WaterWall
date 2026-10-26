/*
 * Covers: Linux capture worker readers, nonblocking verdict ownership, bounded
 * draining, capacity resume, watcher failure and generation settlement.
 * Setup: Real reader/session/WIO/event-loop/process-supervisor implementations;
 * UNIX datagrams substitute for NFQUEUE transport. Worker messages are retained
 * explicitly to exercise cancellation and delivery ordering without threads.
 * Cases: worker-zero fallback and two queues, bounded readiness, verdict EAGAIN,
 * stop-to-ACCEPT, capacity resume, startup refusal, watcher failure, stale tokens,
 * delayed settlement after destruction, and coordinator command-time service.
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
    kFirstQueue = 77
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
    unsigned verdict_attempts;
    unsigned verdicts;
    int      verdict_error;
    wio_t   *io;
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
    uint16_t                   required_padding;
    void                      *tracked_generation;
    void                      *tracked_session;
    unsigned                   generation_frees;
    unsigned                   session_frees;
} reader_fixture_t;

static reader_fixture_t fixture;

ssize_t __real_recvmsg(int fd, struct msghdr *message, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags);
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
        require(message->msg_name != NULL, "capture omitted sender storage");
        *(struct sockaddr_nl *) message->msg_name = (struct sockaddr_nl) {.nl_family = AF_NETLINK};
        message->msg_namelen                      = sizeof(struct sockaddr_nl);
    }
    return result;
}

ssize_t __wrap_sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *address,
                      socklen_t address_length)
{
    const int index = queueIndex(fd);
    if (index < 0)
        return __real_sendto(fd, data, length, flags, address, address_length);
    requireQueueOwner((unsigned) index);
    require((flags & MSG_DONTWAIT) != 0, "capture verdict may block");
    const struct nlmsghdr *header = data;
    require(header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT), "unexpected netlink message");
    const struct nfgenmsg *generic = NLMSG_DATA(header);
    require(ntohs(generic->res_id) == kFirstQueue + index, "verdict used another queue number");
    const struct nfattr         *attribute = NFM_NFA(generic);
    struct nfqnl_msg_verdict_hdr verdict;
    require(NFA_PAYLOAD(attribute) == sizeof(verdict), "invalid verdict shape");
    memoryCopy(&verdict, NFA_DATA(attribute), sizeof(verdict));
    ++fixture.queues[index].verdict_attempts;
    if (fixture.queues[index].verdict_error != 0)
    {
        errno = fixture.queues[index].verdict_error;
        return -1;
    }
    const uint32_t id = ntohl(verdict.id);
    require(id > 0 && id < kPacketIds && fixture.verdicts[id] == UINT32_MAX, "packet received a duplicate verdict");
    fixture.verdicts[id] = ntohl(verdict.verdict);
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
    return (ssize_t) length;
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
        fixture.queues[index].io = io;
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
    require(currentThreadOwnsWorker(wid) && sbufGetLength(buffer) == 28, "delivery changed owner or packet geometry");
    require(sbufGetLeftCapacity(buffer) >= fixture.required_padding, "capture lost reserved chain padding");
    const uint32_t id = GET_BE16((const uint8_t *) sbufGetRawPtr(buffer) + 4);
    require(id > 0 && id < kPacketIds && fixture.verdicts[id] == NF_DROP, "packet published before successful DROP");
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

static capture_device_t *createReaderAt(unsigned first_queue, unsigned queues, unsigned packet_budget)
{
    require(first_queue + queues <= kWorkers, "reader fixture queue inventory exceeded");
    capture_device_t *device   = memoryAllocateZero(sizeof(*device));
    device->name               = stringDuplicate("capture-reader-test");
    device->queue_count        = (uint16_t) queues;
    device->queues             = memoryAllocateZero(queues * sizeof(*device->queues));
    device->queue_restartable  = true;
    device->reader_buffer_pool = devicePoolCreate(getCurrentWorkerBufferPool(), 4096);
    require(device->reader_buffer_pool != NULL, "reader pool creation failed");
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
        fixture.queues[first_queue + i].fd = device->queues[i].fd = pair[0];
        fixture.queues[first_queue + i].peer                      = pair[1];
        fixture.queues[first_queue + i].owner                     = (wid_t) i;
        device->queues[i].number                                  = kFirstQueue + first_queue + i;
    }
    atomicStoreRelaxed(&device->lifecycle, kCaptureLifecycleStarting);
    require(deviceReaderSessionBegin(device->reader_session) != 0, "reader session open failed");
    captureReaderOpen(device);
    return device;
}

static capture_device_t *createReader(unsigned queues, unsigned packet_budget)
{
    return createReaderAt(0, queues, packet_budget);
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

static void sendPacketProtocol(unsigned queue, unsigned id, wid_t destination, uint8_t protocol)
{
    uint8_t packet[28] = {0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17};
    PUT_BE16(packet + 4, id);
    PUT_BE32(packet + 12, UINT32_C(0x0a000001));
    PUT_BE32(packet + 16, UINT32_C(0x0a000002));
    PUT_BE16(packet + 22, 443);
    PUT_BE16(packet + 24, 8);
    packet[9]      = protocol == IPPROTO_TCP ? IPPROTO_TCP : IPPROTO_UDP;
    wid_t selected = kWorkers;
    for (unsigned port = 1; port < 65536; ++port)
    {
        PUT_BE16(packet + 20, port);
        require(deviceFlowAffineWID(packet, sizeof(packet), &selected), "flow hashing rejected the packet");
        if (selected == destination)
            break;
    }
    require(selected == destination, "could not choose the target processing worker");
    packet[9]                                     = protocol;
    _Alignas(ww_max_align_t) uint8_t message[128] = {0};
    struct nlmsghdr                 *header       = (struct nlmsghdr *) message;
    header->nlmsg_type                            = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET;
    struct nfgenmsg *generic                      = NLMSG_DATA(header);
    generic->version                              = NFNETLINK_V0;
    const size_t   base                           = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(*generic)));
    struct nfattr *attribute                      = (struct nfattr *) (void *) (message + base);
    attribute->nfa_type                           = NFQA_PACKET_HDR;
    attribute->nfa_len                            = NFA_LENGTH(sizeof(struct nfqnl_msg_packet_hdr));
    struct nfqnl_msg_packet_hdr *packet_header    = NFA_DATA(attribute);
    packet_header->packet_id                      = htonl(id);
    packet_header->hw_protocol                    = htons(0x0800);
    const size_t offset                           = base + NFA_ALIGN(attribute->nfa_len);
    attribute                                     = (struct nfattr *) (void *) (message + offset);
    attribute->nfa_type                           = NFQA_PAYLOAD;
    attribute->nfa_len                            = NFA_LENGTH(sizeof(packet));
    memoryCopy(NFA_DATA(attribute), packet, sizeof(packet));
    header->nlmsg_len = offset + NFA_ALIGN(attribute->nfa_len);
    require(send(fixture.queues[queue].peer, message, header->nlmsg_len, MSG_DONTWAIT) == (ssize_t) header->nlmsg_len,
            "could not inject queue packet");
}

static void sendPacket(unsigned queue, unsigned id, wid_t destination)
{
    sendPacketProtocol(queue, id, destination, IPPROTO_UDP);
}

static void testReceiveProcessing(unsigned queues)
{
    fixtureSetup();
    capture_device_t *device = createReader(queues, 512);
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
    capture_device_t *device = createReader(1, 512);
    for (unsigned id = 1; id <= 140; ++id)
        sendPacket(0, id, 0);
    require(startReader(device), "bounded reader activation failed");
    runMessage(0);
    require(fixture.queues[0].reads > 0 && fixture.queues[0].reads < 140,
            "one receive root drained the entire unbounded input");
    require(fixture.deliveries[0] > 0 && fixture.deliveries[0] < 140, "bounded read root did not yield delivery");
    runReady(0);
    runMessages();
    require(fixture.deliveries[0] == 140 && fixture.deliveries[1] == 0,
            "level-triggered readiness lost input or split one visible flow across workers");
    destroyReader(device);
    fixtureTeardown();
}

static void testCoordinatorScratchRetainsPadding(void)
{
    fixtureSetup();
    fixture.required_padding = 256;
    globalstateUpdateAllocationPadding(fixture.required_padding);
    capture_device_t *device = createReader(1, 512);
    /* This reader-only fixture bypasses public BringUp. Apply the same finalized
     * geometry; the public lifecycle fixture checks that BringUp installs it. */
    devicePoolUpdatePadding(device->reader_buffer_pool, getCurrentWorkerBufferPool());
    fixture.coordinator = true;
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
        require(fixture.queues[0].reads == 2 && fixture.verdicts[2] == NF_DROP && fixture.verdicts[3] == UINT32_MAX,
                "startup capacity refusal failed to retain the second packet and leave later input unread");

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
    capture_device_t *device = createReader(1, 1);
    sendPacket(0, 1, 1);
    sendPacket(0, 2, 1);
    require(startReader(device), "capacity reader activation failed");
    runMessage(0);
    require(fixture.queues[0].reads == 2 && fixture.queues[0].io->events == 0 && fixture.message_count == 2,
            "capacity refusal did not disable reads while retaining the second packet");
    runMessage(1);
    require(fixture.deliveries[1] == 1 && fixture.message_count == 3 && fixture.messages[2].wid == 0,
            "foreign worker credit release did not wake the reader owner");
    runMessages();
    require(fixture.deliveries[0] == 0 && fixture.deliveries[1] == 2 && fixture.queues[0].io->events == WW_READ &&
                atomicLoadRelaxed(&device->reader_session->output_packets) == 0,
            "capacity wake lost retained input, read interest or credits");
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
    capture_device_t *first  = createReaderAt(0, 1, 512);
    capture_device_t *second = createReaderAt(1, 1, 512);
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
    testBoundedReadiness();
    testCoordinatorScratchRetainsPadding();
    testActiveStartupCommandService(false);
    testActiveStartupCommandService(true);
    testPendingVerdict(false);
    testPendingVerdict(true);
    testCapacityResume();
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
