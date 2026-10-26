#include "capture_linux_nfqueue.h"
#include "capture_linux_private.h"
#include "devices/device_flow_affinity.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "worker_messages.h"
#include "wproc.h"
#include "wtime.h"
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <unistd.h>

typedef struct capture_reader_generation_s capture_reader_generation_t;
typedef struct capture_worker_reader_s
{
    capture_reader_generation_t *generation;
    wid_t                        wid;
    wio_t                       *io;
    wtimer_t                    *verdict_timer;
    atomic_bool                  scheduled;
    atomic_bool                  waiting;
    sbuf_t                      *scratch;
    bool                         verdict_pending;
    uint32_t                     packet_id;
    uint32_t                     verdict;
    uint64_t                     verdict_deadline_us;
    netfilter_packet_result_t    packet_result;
    sbuf_t                      *pending_bufs[kDeviceFragAffinityMaxStagedPerEntry + 1];
    wid_t                        pending_wids[kDeviceFragAffinityMaxStagedPerEntry + 1];
    unsigned                     pending_first;
    unsigned                     pending_count;
    log_rate_limiter_t           discard_log;
    uint64_t                     received;
} capture_worker_reader_t;

struct capture_reader_generation_s
{
    atomic_uint              references;
    atomic_uint              attached;
    quiescence_gate_t        gate;
    capture_device_t        *device;
    device_reader_session_t *session;
    uint16_t                 count;
    uint16_t                 service_next;
    /* Only the serialized lifecycle coordinator accesses these fields. */
    bool                    coordinator_owned;
    proc_command_progress_t command_progress;
    capture_worker_reader_t lanes[];
};

static void captureReaderUnref(capture_reader_generation_t *generation)
{
    if (atomicSubExplicit(&generation->references, 1, memory_order_acq_rel) == 1)
    {
        assert(quiescenceGateIsClosedAndQuiesced(&generation->gate));
        assert(atomicLoadRelaxed(&generation->attached) == 0);
        deviceReaderSessionUnref(generation->session);
        memoryFree(generation);
    }
}

static void captureReaderDetach(capture_worker_reader_t *lane)
{
    assert(currentThreadOwnsWorker(lane->wid));
    if (lane->verdict_timer != NULL)
    {
        wtimerDelete(lane->verdict_timer);
        lane->verdict_timer = NULL;
    }
    if (lane->io != NULL)
    {
        wio_t *io = lane->io;
        lane->io  = NULL;
        weventSetUserData(io, NULL);
        wioReleaseNoClose(io);
        atomicSubExplicit(&lane->generation->attached, 1, memory_order_release);
        captureReaderUnref(lane->generation);
    }
}

static void captureReaderMessage(worker_t *worker, void *arg1, void *arg2, void *arg3);
static void captureReaderCancel(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                  arg3;
    capture_worker_reader_t *lane = arg1;
    if (arg2 != NULL &&
        (reason == kWorkerMessageCancelEnqueueFailure ||
         (reason == kWorkerMessageCancelTargetUnavailable && quiescenceGateIsActive(&lane->generation->gate))))
    {
        LOGF("CaptureDevice: required receive notification could not reach its worker");
        abortProgramNow(1);
    }
    atomicStoreExplicit(&lane->scheduled, false, memory_order_release);
    captureReaderUnref(lane->generation);
}

static bool captureReaderSchedule(capture_worker_reader_t *lane, bool required)
{
    if (atomicExchangeExplicit(&lane->scheduled, true, memory_order_acq_rel))
        return true;
    atomicIncExplicit(&lane->generation->references, memory_order_relaxed);
    return sendWorkerMessageForceQueueWithCleanup(lane->wid,
                                                  (WorkerMessageCallback) captureReaderMessage,
                                                  captureReaderCancel,
                                                  lane,
                                                  required ? lane : NULL,
                                                  NULL) == kWorkerMessageSubmitAccepted;
}

void captureReaderCapacityReady(void *context)
{
    capture_device_t            *device = context;
    capture_reader_generation_t *generation =
        (capture_reader_generation_t *) atomicLoadExplicit(&device->reader_notify, memory_order_acquire);
    if (generation == NULL)
        return;
    /* Session notification admission pins the device and reader generation. */
    for (uint16_t i = 0; i < generation->count; ++i)
        if (atomicLoadExplicit(&generation->lanes[i].waiting, memory_order_acquire))
            discard captureReaderSchedule(&generation->lanes[i], true);
}

static bool captureReaderPost(capture_worker_reader_t *lane)
{
    while (lane->pending_first < lane->pending_count)
    {
        const unsigned i = lane->pending_first;
        atomicStoreExplicit(&lane->waiting, true, memory_order_release);
        const device_reader_post_result_e result =
            deviceReaderSessionTryPost(lane->generation->session, lane->pending_wids[i], &lane->pending_bufs[i], 1);
        if (result == kDeviceReaderPostCapacity)
            return false;
        atomicStoreExplicit(&lane->waiting, false, memory_order_release);
        ++lane->pending_first;
    }
    lane->pending_first = lane->pending_count = 0;
    return true;
}

static void captureReaderPrepare(capture_worker_reader_t *lane, sbuf_t *buffer)
{
    device_frag_affinity_result_t       fragment;
    const device_frag_affinity_action_t action = deviceFragAffinityOffer(
        lane->generation->session->frag_affinity, sbufGetRawPtr(buffer), sbufGetLength(buffer), buffer, &fragment);
    assert(lane->pending_count == 0);
    if (action == kDeviceFragAffinityConsumedDrop || action == kDeviceFragAffinityStaged)
        return;
    if (action == kDeviceFragAffinityComplete)
        buffer = fragment.completed;
    if (action == kDeviceFragAffinityDispatch)
    {
        for (unsigned i = 0; i < fragment.released_count; ++i)
        {
            lane->pending_bufs[lane->pending_count]   = fragment.released[i];
            lane->pending_wids[lane->pending_count++] = fragment.wid;
        }
    }
    /* Receive steering is a locality choice. Flow owners are selected by
     * consumers after any transformations that expose their transport tuple. */
    const wid_t wid =
        action == kDeviceFragAffinityDispatch
            ? fragment.wid
            : deviceReaderSelectWID(lane->generation->session, lane->wid, lane->generation->count, buffer);
    lane->pending_bufs[lane->pending_count]   = buffer;
    lane->pending_wids[lane->pending_count++] = wid;
}

static void captureReaderDiscard(capture_worker_reader_t *lane)
{
    const log_rate_limiter_report_t report = logRateLimiterRecord(&lane->discard_log, kCaptureDiscardReportIntervalMs);
    if (report.should_log)
        LOGW("CaptureDevice: discarded %llu malformed, truncated or oversized packets (total=%llu)",
             LLU(report.events),
             LLU(report.total));
}

/* One syscall primitive at a time. A read record stays in scratch until its
 * verdict succeeds. Stop can convert an unsent DROP to ACCEPT without exposing
 * the packet through both the host stack and WaterWall. */
static netfilter_verdict_result_t captureReaderVerdict(capture_worker_reader_t *lane, bool active)
{
    capture_linux_queue_t *queue = &lane->generation->device->queues[lane->wid];
    if (! active)
        lane->verdict = NF_ACCEPT;
    if ((uint64_t) getHRTimeUs() >= lane->verdict_deadline_us)
    {
        errno = ETIMEDOUT;
        return kNetfilterVerdictError;
    }
    const netfilter_verdict_result_t result =
        netfilterTrySendVerdict(queue->fd, queue->number, lane->packet_id, lane->verdict);
    if (result != kNetfilterVerdictSent)
        return result;
    lane->verdict_pending = false;
    if (active && lane->verdict == NF_DROP && lane->packet_result == kNetfilterPacketReady)
    {
        sbuf_t *buffer = lane->scratch;
        lane->scratch  = NULL;
        captureReaderPrepare(lane, buffer);
    }
    else if (active && lane->verdict == NF_DROP)
        captureReaderDiscard(lane);
    return result;
}

static netfilter_packet_result_t captureReaderReceive(capture_worker_reader_t *lane, buffer_pool_t *pool, bool active)
{
    if (lane->scratch == NULL)
        lane->scratch =
            pool != NULL
                ? bufferpoolGetBestFit(pool, kNetfilterReadBufferSize, 0)
                : sbufCreateWithPadding(kNetfilterReadBufferSize,
                                        bufferpoolGetSmallBufferPadding(lane->generation->device->reader_buffer_pool));
    sbufReset(lane->scratch);
    const netfilter_packet_result_t result =
        netfilterReceivePacket(lane->generation->device->queues[lane->wid].fd, lane->scratch, &lane->packet_id);
    if (result == kNetfilterPacketReady || result == kNetfilterPacketDiscarded ||
        result == kNetfilterPacketMalformedDiscarded)
    {
        lane->packet_result       = result;
        lane->verdict             = active ? NF_DROP : NF_ACCEPT;
        lane->verdict_pending     = true;
        lane->verdict_deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000;
        ++lane->received;
    }
    return result;
}

static void captureReaderRun(capture_worker_reader_t *lane, worker_t *worker);
static void captureReaderOnReady(wio_t *io)
{
    capture_worker_reader_t *lane = weventGetUserdata(io);
    if (lane != NULL)
        captureReaderRun(lane, getCurrentWorker());
}

static void captureReaderTimeout(wtimer_t *timer)
{
    capture_worker_reader_t *lane = weventGetUserdata(timer);
    lane->verdict_timer           = NULL;
    captureReaderRun(lane, getCurrentWorker());
}

static bool captureReaderRead(capture_worker_reader_t *lane, worker_t *worker)
{
    capture_device_t *device = lane->generation->device;
    unsigned          bytes  = 0;
    for (unsigned attempts = 0; attempts < 256 && bytes < 256U * 1024U; ++attempts)
    {
        if (! captureLifecycleIsActive(captureLifecycleLoad(&device->lifecycle)))
            return true;
        if (! captureReaderPost(lane))
            return true;
        if (lane->verdict_pending)
        {
            const netfilter_verdict_result_t result =
                captureReaderVerdict(lane, atomicLoadRelaxed(&device->capture_active));
            if (result == kNetfilterVerdictError)
                return false;
            if (result == kNetfilterVerdictYield)
                discard captureReaderSchedule(lane, true);
            if (result != kNetfilterVerdictSent)
                return true;
            continue;
        }
        const netfilter_packet_result_t result =
            captureReaderReceive(lane, worker->buffer_pool, atomicLoadRelaxed(&device->capture_active));
        if (result == kNetfilterPacketError || result == kNetfilterPacketEof)
            return false;
        if (result == kNetfilterPacketYield)
            discard captureReaderSchedule(lane, true);
        if (result == kNetfilterPacketWouldBlock || result == kNetfilterPacketYield)
            return true;
        bytes += sbufGetLength(lane->scratch);
    }
    discard captureReaderPost(lane);
    return true;
}

static void captureReaderRun(capture_worker_reader_t *lane, worker_t *worker)
{
    capture_reader_generation_t *generation = lane->generation;
    assert(worker->wid == lane->wid);
    if (! quiescenceGateEnter(&generation->gate))
    {
        captureReaderDetach(lane);
        return;
    }
    capture_device_t *device = generation->device;
    bool              failed = false;
    if (lane->io == NULL)
    {
        const int fd = device->queues[lane->wid].fd;
        wio_t    *io = wioGet(worker->loop, fd);
        if (io == NULL || wioGetFD(io) != fd)
        {
            if (io != NULL)
                wioReleaseNoClose(io);
            failed = true;
        }
        else
        {
            lane->io = io;
            atomicIncExplicit(&generation->references, memory_order_relaxed);
            atomicIncExplicit(&generation->attached, memory_order_relaxed);
            weventSetUserData(io, lane);
        }
    }
    if (! failed)
    {
        device_reader_burst_t burst;
        const bool            local = deviceReaderSessionTryBeginBurst(generation->session, worker, &burst);
        failed                      = ! captureReaderRead(lane, worker);
        if (local)
            deviceReaderSessionEndBurst(&burst);
        if (! lane->verdict_pending && lane->verdict_timer != NULL)
        {
            wtimerDelete(lane->verdict_timer);
            lane->verdict_timer = NULL;
        }
        if (lane->verdict_pending && lane->verdict_timer == NULL && ! failed)
        {
            const uint64_t now = (uint64_t) getHRTimeUs();
            const uint32_t delay =
                lane->verdict_deadline_us > now ? (uint32_t) ((lane->verdict_deadline_us - now + 999) / 1000) : 1;
            lane->verdict_timer = wtimerAdd(worker->loop, captureReaderTimeout, delay, 1);
            if (lane->verdict_timer == NULL)
                failed = true;
            else
                weventSetUserData(lane->verdict_timer, lane);
        }
        wioDel(lane->io, WW_READ | WW_WRITE);
        if (! failed && ! atomicLoadExplicit(&lane->waiting, memory_order_acquire) &&
            captureLifecycleIsActive(captureLifecycleLoad(&device->lifecycle)) &&
            quiescenceGateIsActive(&generation->gate))
            failed = wioAdd(lane->io, captureReaderOnReady, lane->verdict_pending ? WW_WRITE : WW_READ) != 0;
    }
    capture_lifecycle_state_t from;
    const bool                transitioned = failed && captureLifecycleTransitionToFailed(&device->lifecycle, &from);
    if (transitioned)
    {
        atomicStoreRelaxed(&device->up, false);
        atomicStoreRelaxed(&device->capture_active, false);
        deviceReaderSessionEndRequest(generation->session);
    }
    const bool shutdown = transitioned && from == kCaptureLifecycleUp;
    quiescenceGateLeave(&generation->gate);
    if (shutdown)
    {
        LOGE("CaptureDevice: worker %u receive/verdict failure: %s", (unsigned) worker->wid, strerror(errno));
        if (! requestProgramShutdown(1))
            abortProgramNow(1);
    }
}

static void captureReaderMessage(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                      arg2;
    discard                      arg3;
    capture_worker_reader_t     *lane       = arg1;
    capture_reader_generation_t *generation = lane->generation;
    atomicStoreExplicit(&lane->scheduled, false, memory_order_release);
    captureReaderRun(lane, worker);
    captureReaderUnref(generation);
}

void captureReaderOpen(capture_device_t *device)
{
    assert(device->reader == NULL && device->queue_count > 0);
    capture_reader_generation_t *generation =
        memoryAllocateZero(sizeof(*generation) + device->queue_count * sizeof(generation->lanes[0]));
    generation->device            = device;
    generation->session           = device->reader_session;
    generation->count             = device->queue_count;
    generation->coordinator_owned = true;
    atomicStoreRelaxed(&generation->references, 1);
    deviceReaderSessionRef(generation->session);
    quiescenceGateInit(&generation->gate);
    device->reader = generation;
    for (uint16_t i = 0; i < generation->count; ++i)
    {
        generation->lanes[i].generation = generation;
        generation->lanes[i].wid        = (wid_t) i;
    }
    atomicStoreExplicit(&device->reader_notify, (uintptr_t) generation, memory_order_release);
    generation->command_progress = (proc_command_progress_t) {.callback = captureReaderService, .context = device};
    procCommandProgressRegister(&generation->command_progress);
}

bool captureReaderStart(capture_device_t *device)
{
    capture_reader_generation_t *generation = device->reader;
    assert(generation != NULL);
    if (! quiescenceGateOpen(&generation->gate))
        return false;
    generation->coordinator_owned = false;
    for (uint16_t i = 0; i < generation->count; ++i)
        if (! captureReaderSchedule(&generation->lanes[i], false))
            return false;
    return true;
}

void captureReaderCloseRequest(capture_device_t *device)
{
    capture_reader_generation_t *generation = device->reader;
    if (generation == NULL)
        return;
    quiescenceGateClose(&generation->gate);
    for (uint16_t i = 0; i < generation->count; ++i)
        discard captureReaderSchedule(&generation->lanes[i], true);
}

void capturedeviceWorkerQuiesce(capture_device_t *device, wid_t wid)
{
    assert(currentThreadOwnsWorker(wid));
    if (device->reader != NULL && wid < device->reader->count)
        captureReaderDetach(&device->reader->lanes[wid]);
}

static void captureReaderTakeCoordinatorOwnership(capture_reader_generation_t *generation)
{
    if (generation->coordinator_owned)
        return;
    generation->coordinator_owned = true;
    /* Worker watchers and admitted callbacks have surrendered native ownership.
     * Keep unsent verdicts for coordinator NF_ACCEPT service during rule cleanup. */
    for (uint16_t i = 0; i < generation->count; ++i)
    {
        capture_worker_reader_t *lane = &generation->lanes[i];
        for (unsigned j = lane->pending_first; j < lane->pending_count; ++j)
            sbufDestroy(lane->pending_bufs[j]);
        lane->pending_first = lane->pending_count = 0;
        if (lane->verdict_pending)
            lane->verdict_deadline_us = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000;
    }
}

void captureReaderCloseWait(capture_device_t *device)
{
    capture_reader_generation_t *generation = device->reader;
    if (generation == NULL)
        return;
    quiescenceGateWaitQuiesced(&generation->gate, quiescenceGateYieldThread, NULL);
    worker_t *worker = tryGetCurrentWorker();
    if (worker != NULL && worker->wid < generation->count)
        captureReaderDetach(&generation->lanes[worker->wid]);
    while (atomicLoadExplicit(&generation->attached, memory_order_acquire) != 0)
        quiescenceGateYieldThread(NULL);
    captureReaderTakeCoordinatorOwnership(generation);
}

static bool captureReaderServicePass(capture_device_t *device)
{
    capture_reader_generation_t *generation = device->reader;
    if (generation == NULL)
        return true;
    /* Before startup releases workers_run_flag, the coordinator remains the
     * sole native reader even after activation messages were queued. Otherwise
     * closed/quiesced admission plus detached watchers proves the handoff. */
    assert(generation->coordinator_owned || ! atomicLoadExplicit(&GSTATE.workers_run_flag, memory_order_acquire));
    assert(atomicLoadRelaxed(&generation->attached) == 0);
    /* Bound the whole device's work, including malformed input and EINTR.
     * Round robin prevents an active queue from starving another queue. */
    bool     quiet = true;
    unsigned bytes = 0;
    for (unsigned attempts = 0; attempts < 256 && bytes < 256U * 1024U; ++attempts)
    {
        capture_worker_reader_t *lane = &generation->lanes[generation->service_next];
        generation->service_next      = (uint16_t) ((generation->service_next + 1U) % generation->count);
        capture_linux_queue_t *queue  = &device->queues[lane->wid];
        if (queue->fd < 0)
            continue;
        /* An activated device must keep capturing while later startup commands
         * run. Detached buffers enter the session FIFO; no tunnel callback runs
         * until its worker starts. Inactive and stopped devices accept instead. */
        const bool active = atomicLoadRelaxed(&device->capture_active);
        if (active && ! captureReaderPost(lane))
        {
            quiet = false;
            continue;
        }
        bool failed = false;
        if (lane->verdict_pending)
        {
            quiet  = false;
            failed = captureReaderVerdict(lane, active) == kNetfilterVerdictError;
        }
        else
        {
            const netfilter_packet_result_t result = captureReaderReceive(lane, NULL, active);
            quiet &= result == kNetfilterPacketWouldBlock;
            failed = result == kNetfilterPacketError || result == kNetfilterPacketEof;
            if (lane->verdict_pending)
                bytes += sbufGetLength(lane->scratch);
        }
        if (failed)
        {
            LOGE("CaptureDevice: coordinator queue %u failed: %s", queue->number, strerror(errno));
            close(queue->fd);
            queue->fd                 = -1;
            device->queue_restartable = false;
            lane->verdict_pending     = false;
            capture_lifecycle_state_t previous;
            if (captureLifecycleTransitionToFailed(&device->lifecycle, &previous))
            {
                atomicStoreRelaxed(&device->capture_active, false);
                atomicStoreRelaxed(&device->up, false);
                deviceReaderSessionEndRequest(generation->session);
                if (previous == kCaptureLifecycleUp)
                    startupFailureRecord(1);
            }
        }
    }
    return quiet;
}

void captureReaderService(void *context)
{
    capture_device_t            *device     = context;
    capture_reader_generation_t *generation = device->reader;
    if (generation == NULL)
        return;
    if (! generation->coordinator_owned)
    {
        if (quiescenceGateIsClosedAndQuiesced(&generation->gate) &&
            atomicLoadExplicit(&generation->attached, memory_order_acquire) == 0)
            captureReaderTakeCoordinatorOwnership(generation);
        else if (atomicLoadExplicit(&GSTATE.workers_run_flag, memory_order_acquire))
            return;
    }
    discard captureReaderServicePass(device);
}

bool captureReaderDrain(capture_device_t *device)
{
    if (device->reader == NULL)
        return true;
    const uint64_t deadline = (uint64_t) getHRTimeUs() + (uint64_t) kNetfilterIoDeadlineMs * 1000;
    uint64_t       initial  = 0;
    for (uint16_t i = 0; i < device->reader->count; ++i)
        initial += device->reader->lanes[i].received;
    /* A complete quiet pass must actually read EAGAIN from every lane; merely
     * completing a pending verdict does not prove its queue empty. */
    for (;;)
    {
        if (captureReaderServicePass(device))
            return device->queue_restartable;
        /* A verdict-stalled device must not strand other detached queues while
         * its own residual drain waits for kernel send capacity. */
        discard  procCommandProgressRun();
        uint64_t received = 0;
        for (uint16_t i = 0; i < device->reader->count; ++i)
            received += device->reader->lanes[i].received;
        if (received - initial >= kNetfilterResidualPacketBudget || (uint64_t) getHRTimeUs() >= deadline)
            break;
        /* Only the exclusive lifecycle coordinator may wait. Normal reads and
         * supervisor progress callbacks never sleep or poll for capacity. */
        wwSleepMS(1);
    }
    LOGE("CaptureDevice: residual queue drain exceeded its packet/time bound");
    return false;
}

void captureReaderDestroy(capture_device_t *device)
{
    capture_reader_generation_t *generation = device->reader;
    if (generation == NULL)
        return;
    assert(quiescenceGateIsClosedAndQuiesced(&generation->gate));
    assert(atomicLoadRelaxed(&generation->attached) == 0);
    for (uint16_t i = 0; i < generation->count; ++i)
    {
        capture_worker_reader_t *lane = &generation->lanes[i];
        if (lane->scratch != NULL)
            sbufDestroy(lane->scratch);
        for (unsigned j = lane->pending_first; j < lane->pending_count; ++j)
            sbufDestroy(lane->pending_bufs[j]);
    }
    procCommandProgressUnregister(&generation->command_progress);
    atomicStoreExplicit(&device->reader_notify, (uintptr_t) NULL, memory_order_release);
    device->reader = NULL;
    captureReaderUnref(generation);
}
