#include "devices/device_flow_affinity.h"
#include "devices/device_pool.h"
#include "global_state.h"
#include "ipv4_packet_view.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"
#include "tun_linux_offload.h"
#include "tun_linux_private.h"
#include "worker_messages.h"
#include <errno.h>
#include <unistd.h>

typedef struct tun_offload_reader_s
{
    sbuf_t                  *scratch;
    tun_linux_offload_plan_t pending_plan;
    bool                     pending;
    bool                     waiting_for_capacity;
    uint64_t                 ordinary_records;
    uint64_t                 gso_aggregates;
    uint64_t                 checksum_completions;
    uint64_t                 malformed_records;
    uint64_t                 unsupported_records;
    uint64_t                 oversized_records;
} tun_offload_reader_t;

static atomic_log_rate_limiter_t tun_offload_reject_log;

static const char *tunOffloadRejectName(tun_linux_offload_reject_t reject)
{
    switch (reject)
    {
    case kTunLinuxOffloadMalformed:
        return "malformed";
    case kTunLinuxOffloadUnsupported:
        return "unsupported offload metadata";
    case kTunLinuxOffloadOversized:
        return "oversized";
    case kTunLinuxOffloadAccept:
        break;
    }
    return "unexpected";
}

static void tunOffloadCountReject(tun_device_t *tdev, tun_offload_reader_t *reader, tun_linux_offload_reject_t reject)
{
    switch (reject)
    {
    case kTunLinuxOffloadMalformed:
        reader->malformed_records++;
        break;
    case kTunLinuxOffloadUnsupported:
        reader->unsupported_records++;
        break;
    case kTunLinuxOffloadOversized:
        reader->oversized_records++;
        break;
    case kTunLinuxOffloadAccept:
        return;
    }
    if (atomicLogRateLimiterShouldLog(&tun_offload_reject_log, kTunOffloadLogIntervalMs))
    {
        LOGW("TunDevice: dropping %s TUN offload record on %s", tunOffloadRejectName(reject), tdev->name);
    }
}

typedef struct tun_offload_work_s
{
    sbuf_t                  *aggregate;
    tun_linux_offload_plan_t plan;
    uint32_t                 next_payload_offset;
    size_t                   output_charge;
    uint16_t                 padding;
} tun_offload_work_t;

static void tunOffloadWorkCleanup(void *context)
{
    tun_offload_work_t *work = context;
    if (work->aggregate != NULL)
    {
        sbufDestroy(work->aggregate);
    }
    memoryFree(work);
}

/* The session admits this callback on the selected event worker and keeps the
 * aggregate at its FIFO head across continuations. One prepaid output allowance
 * is sufficient because delivery transfers each segment before the next one is
 * allocated; downstream retention follows the ordinary packet-chain contract. */
static bool tunOffloadWorkStep(device_reader_session_t *session, void *context, wid_t wid,
                               device_reader_work_budget_t *budget)
{
    tun_offload_work_t *work = context;
    assert(currentThreadOwnsWorker(wid));
    buffer_pool_t *pool    = getWorkerBufferPool(wid);
    uint32_t       emitted = 0;
    /* The direct trusted TUN/PTC pair accepts assured TCPv4 aggregates intact.
     * Preflight has validated an exact, unfragmented packet <= UINT16_MAX.
     * Delivery uses the same selected worker and FIFO as segmented input. */
    tun_device_t *device = session->device;
    assert(work->plan.action != kTunLinuxOffloadSegment || (device->gso_enabled && work->output_charge > 0));
    const bool intact_tcp_gso =
        work->plan.action == kTunLinuxOffloadSegment && device->trusted_checksums && work->plan.transport_assured;
    if (work->plan.action != kTunLinuxOffloadSegment || intact_tcp_gso)
    {
        assert(work->plan.transport_assured || work->plan.action == kTunLinuxOffloadChecksum);
        const uint32_t length = sbufGetLength(work->aggregate);
        if (budget->packets == 0 || budget->bytes < length)
        {
            return false;
        }
        if (work->plan.action == kTunLinuxOffloadChecksum && ! work->plan.transport_assured)
        {
            tunLinuxOffloadCompleteChecksum(sbufGetMutablePtr(work->aggregate), &work->plan);
        }
        sbuf_t *output  = work->aggregate;
        work->aggregate = NULL;
        --budget->packets;
        budget->bytes -= length;
        if (intact_tcp_gso)
        {
            atomic_fetch_add_explicit(&device->gso_intact_aggregates, 1, memory_order_relaxed);
        }
        tunDeliverPacket(session->device, output, wid);
        return true;
    }
    while (work->next_payload_offset < work->plan.payload_length && budget->packets > 0)
    {
        const uint32_t payload_length = min(work->plan.gso_size, work->plan.payload_length - work->next_payload_offset);
        const uint32_t segment_length = work->plan.header_length + payload_length;
        if (segment_length > budget->bytes)
        {
            break;
        }
        buffer_pool_fit_t fit;
        if (UNLIKELY(! bufferpoolQueryBestFit(pool, segment_length, work->padding, &fit)))
        {
            LOGF("TunDevice: GSO worker output has unrepresentable buffer geometry");
            abortProgramNow(1);
        }
        /* A later startup config can increase the shared worker pool's padding.
         * Keep this chain's prepaid bound with an exact-sized ordinary buffer
         * when the current pool tier no longer fits that allowance. */
        sbuf_t *output = fit.allocation_charge <= work->output_charge
                             ? bufferpoolGetBestFit(pool, segment_length, work->padding)
                             : sbufCreateWithPadding(segment_length, work->padding);
        if (UNLIKELY(output == NULL || sbufGetAllocationCharge(output) > work->output_charge))
        {
            LOGF("TunDevice: GSO output allocation violated its prepaid worker allowance");
            abortProgramNow(1);
        }
        uint32_t built_length = 0;
        if (UNLIKELY(! tunLinuxOffloadPrepareSegment(sbufGetRawPtr(work->aggregate),
                                                     &work->plan,
                                                     work->next_payload_offset,
                                                     sbufGetMutablePtr(output),
                                                     sbufGetMaximumWriteableSize(output),
                                                     &built_length) ||
                     built_length != segment_length))
        {
            LOGF("TunDevice: GSO worker segmentation violated successful aggregate preflight");
            abortProgramNow(1);
        }
        sbufSetLength(output, built_length);
        if (! work->plan.transport_assured)
        {
            tunLinuxOffloadCompleteSegment(sbufGetMutablePtr(output), built_length);
        }
        /* Preflight checked shape and metadata. The destination stack uses its
         * receive policy for this generated segment. */
        tunDeliverPacket(session->device, output, wid);
        work->next_payload_offset += payload_length;
        budget->bytes -= segment_length;
        --budget->packets;
        emitted++;
    }
    tun_device_t *tdev = session->device;
    atomic_fetch_add_explicit(&tdev->gso_generated_segments, emitted, memory_order_relaxed);
    if (work->next_payload_offset != work->plan.payload_length)
    {
        return false;
    }
    bufferpoolReuseBuffer(pool, work->aggregate);
    work->aggregate = NULL;
    return true;
}

/* Only complete TCP/UDP records with ordinary transport checksum coordinates
 * bypass reader fragment handling. Completion cannot change their flow key.
 * Other metadata retains generic reader-side completion before affinity. */
static bool tunOffloadCanDeferChecksum(const uint8_t *ip, const tun_linux_offload_plan_t *plan)
{
    assert(plan->action == kTunLinuxOffloadChecksum && ! plan->transport_assured);
    if ((ip[0] >> 4U) == 4)
    {
        ipv4_packet_view_t packet = {0};
        if (! ipv4packetviewParse(ip, plan->ip_length, &packet) || packet.ip_total_length != plan->ip_length ||
            packet.fragmented)
        {
            return false;
        }
        const bool tcp = packet.protocol == 6 && ipv4packetviewParseTcp(ip, plan->ip_length, &packet);
        const bool udp = packet.protocol == 17 && ipv4packetviewParseUdp(ip, plan->ip_length, &packet);
        return (tcp || udp) && plan->checksum_start == packet.transport_offset &&
               plan->checksum_field == packet.transport_offset + (tcp ? 16U : 6U);
    }
    /* Plain IPv6 TCP/UDP has no fragment/extension header to normalize. */
    if ((ip[0] >> 4U) == 6 && plan->ip_length >= 48 && GET_BE16(ip + 4) + 40U == plan->ip_length)
    {
        const uint32_t transport_length = plan->ip_length - 40U;
        const bool     tcp              = ip[6] == 6 && transport_length >= 20 && (ip[52] >> 4U) >= 5 &&
                         (uint32_t) (ip[52] >> 4U) * 4U <= transport_length;
        const bool udp = ip[6] == 17 && GET_BE16(ip + 44) >= 8 && GET_BE16(ip + 44) <= transport_length;
        return (tcp || udp) && plan->checksum_start == 40 && plan->checksum_field == 40U + (tcp ? 16U : 6U);
    }
    return false;
}

/* Preserve one unadmitted record in scratch when the input budget is full.
 * GSO/assured admission transfers scratch itself. Ordinary checksum work copies
 * into compact packet storage and leaves scratch available for batched reads. */
typedef struct tun_reader_generation_s tun_reader_generation_t;
typedef struct tun_worker_reader_s
{
    tun_reader_generation_t *generation;
    wid_t                    wid;
    int                      fd;
    wio_t                   *io;
    atomic_bool              scheduled;
    atomic_bool              waiting;
    tun_offload_reader_t     offload;
    sbuf_t                  *pending_bufs[kDeviceFragAffinityMaxStagedPerEntry + 1];
    wid_t                    pending_wids[kDeviceFragAffinityMaxStagedPerEntry + 1];
    unsigned                 pending_count;
    unsigned                 pending_first;
} tun_worker_reader_t;

struct tun_reader_generation_s
{
    atomic_uint              references;
    atomic_uint              attached;
    quiescence_gate_t        gate;
    tun_device_t            *device;
    device_reader_session_t *session;
    uint16_t                 count;
    tun_worker_reader_t      lanes[];
};

static void tunReaderUnref(tun_reader_generation_t *generation)
{
    if (atomicSubExplicit(&generation->references, 1, memory_order_acq_rel) == 1)
    {
        assert(quiescenceGateIsClosedAndQuiesced(&generation->gate));
        assert(atomicLoadRelaxed(&generation->attached) == 0);
        deviceReaderSessionUnref(generation->session);
        memoryFree(generation);
    }
}

static void tunReaderDetach(tun_worker_reader_t *lane)
{
    assert(currentThreadOwnsWorker(lane->wid));
    if (lane->io != NULL)
    {
        wio_t *io = lane->io;
        lane->io  = NULL;
        weventSetUserData(io, NULL);
        wioReleaseNoClose(io);
        atomicSubExplicit(&lane->generation->attached, 1, memory_order_release);
        tunReaderUnref(lane->generation);
    }
}

static void tunReaderMessage(worker_t *worker, void *arg1, void *arg2, void *arg3);
static void tunReaderMessageCancel(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard              arg3;
    tun_worker_reader_t *lane = arg1;
    if (arg2 != NULL &&
        (reason == kWorkerMessageCancelEnqueueFailure ||
         (reason == kWorkerMessageCancelTargetUnavailable && quiescenceGateIsActive(&lane->generation->gate))))
    {
        LOGF("TunDevice: required receive notification could not reach its worker");
        abortProgramNow(1);
    }
    atomicStoreExplicit(&lane->scheduled, false, memory_order_release);
    tunReaderUnref(lane->generation);
}

static bool tunReaderSchedule(tun_worker_reader_t *lane, bool required)
{
    if (atomicExchangeExplicit(&lane->scheduled, true, memory_order_acq_rel))
        return true;
    atomicIncExplicit(&lane->generation->references, memory_order_relaxed);
    return sendWorkerMessageForceQueueWithCleanup(lane->wid,
                                                  (WorkerMessageCallback) tunReaderMessage,
                                                  tunReaderMessageCancel,
                                                  lane,
                                                  required ? lane : NULL,
                                                  NULL) == kWorkerMessageSubmitAccepted;
}

void tunReaderCapacityReady(void *context)
{
    tun_device_t            *device = context;
    tun_reader_generation_t *generation =
        (tun_reader_generation_t *) atomicLoadExplicit(&device->reader_notify, memory_order_acquire);
    if (generation == NULL)
        return;
    /* Session notification admission keeps the device and generation alive. */
    for (uint16_t i = 0; i < generation->count; ++i)
        if (atomicLoadExplicit(&generation->lanes[i].waiting, memory_order_acquire))
            discard tunReaderSchedule(&generation->lanes[i], true);
}

static bool tunReaderPostOffload(tun_worker_reader_t *lane, worker_t *worker)
{
    tun_device_t         *tdev   = lane->generation->device;
    tun_offload_reader_t *reader = &lane->offload;
    wid_t                 wid;
    if (! deviceFlowAffineWID(sbufGetRawPtr(reader->scratch), sbufGetLength(reader->scratch), &wid))
    {
        LOGF("TunDevice: validated offload record has no flow identity");
        abortProgramNow(1);
    }
    const bool compact =
        reader->pending_plan.action == kTunLinuxOffloadChecksum && ! reader->pending_plan.transport_assured;
    const uint16_t padding = max(bufferpoolGetLargeBufferPadding(worker->buffer_pool), (uint16_t) kTunVirtioHeaderSize);
    buffer_pool_fit_t fit  = {0};
    if (compact && ! bufferpoolQueryBestFit(worker->buffer_pool, reader->pending_plan.ip_length, padding, &fit))
    {
        LOGF("TunDevice: invalid checksum work geometry");
        abortProgramNow(1);
    }
    const size_t output_charge = compact || ! tdev->gso_enabled ? 0 : tdev->gso_output_charge[wid];
    const size_t charge        = (compact ? fit.allocation_charge : sbufGetAllocationCharge(reader->scratch)) +
                          sizeof(tun_offload_work_t) + output_charge;
    const unsigned packet_slots = compact ? 1 : 2;
    atomicStoreExplicit(&lane->waiting, true, memory_order_release);
    if (! deviceReaderSessionTryReserveWork(tdev->reader_session, charge, packet_slots))
        return false;
    atomicStoreExplicit(&lane->waiting, false, memory_order_release);
    tun_offload_work_t *work = memoryAllocate(sizeof(*work));
    *work                    = (tun_offload_work_t) {.aggregate     = reader->scratch,
                                                     .plan          = reader->pending_plan,
                                                     .output_charge = output_charge,
                                                     .padding       = tdev->offload_output_padding[wid]};
    if (compact)
    {
        work->aggregate = bufferpoolGetBestFit(worker->buffer_pool, work->plan.ip_length, padding);
        memoryCopy(sbufGetMutablePtr(work->aggregate), sbufGetRawPtr(reader->scratch), work->plan.ip_length);
        sbufSetLength(work->aggregate, work->plan.ip_length);
    }
    else
        reader->scratch = NULL;
    reader->pending = false;
    discard deviceReaderSessionPostWork(
        tdev->reader_session, wid, work, tunOffloadWorkStep, tunOffloadWorkCleanup, charge, packet_slots);
    return true;
}

static bool tunReaderPostPackets(tun_worker_reader_t *lane)
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

static void tunReaderPreparePacket(tun_worker_reader_t *lane, sbuf_t *buf)
{
    device_frag_affinity_result_t       fragment;
    const device_frag_affinity_action_t action = deviceFragAffinityOffer(
        lane->generation->session->frag_affinity, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &fragment);
    assert(lane->pending_count == 0);
    if (action == kDeviceFragAffinityConsumedDrop || action == kDeviceFragAffinityStaged)
        return;
    if (action == kDeviceFragAffinityComplete)
        buf = fragment.completed;
    if (action == kDeviceFragAffinityDispatch)
    {
        for (unsigned i = 0; i < fragment.released_count; ++i)
        {
            lane->pending_bufs[lane->pending_count]   = fragment.released[i];
            lane->pending_wids[lane->pending_count++] = fragment.wid;
        }
    }
    wid_t wid = fragment.wid;
    if (action != kDeviceFragAffinityDispatch && ! deviceFlowAffineWID(sbufGetRawPtr(buf), sbufGetLength(buf), &wid))
        wid = getNextDistributionWID();
    lane->pending_bufs[lane->pending_count]   = buf;
    lane->pending_wids[lane->pending_count++] = wid;
}

/* One owner callback does bounded native I/O. Capacity refusal retains the
 * already-read record and disables readiness until a credit notification. */
static bool tunReaderDrain(tun_worker_reader_t *lane, worker_t *worker)
{
    tun_device_t         *tdev   = lane->generation->device;
    tun_offload_reader_t *reader = &lane->offload;
    uint32_t              bytes  = 0;
    for (unsigned attempts = 0; attempts < 256 && bytes < 256U * 1024U; ++attempts)
    {
        if (! tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
            return true;
        if (! tunReaderPostPackets(lane) || (reader->pending && ! tunReaderPostOffload(lane, worker)))
            return true;
        const uint32_t capacity = tdev->checksum_offload_enabled ? kTunOffloadPacketStorageCapacity : tdev->mtu;
        const uint16_t padding =
            max(bufferpoolGetLargeBufferPadding(worker->buffer_pool), (uint16_t) kTunVirtioHeaderSize);
        if (reader->scratch == NULL)
            reader->scratch = bufferpoolGetBestFit(worker->buffer_pool, capacity, padding);
        sbufReset(reader->scratch);
        if (tdev->checksum_offload_enabled)
            sbufShiftLeft(reader->scratch, kTunVirtioHeaderSize);
        const ssize_t nread = read(lane->fd,
                                   sbufGetMutablePtr(reader->scratch),
                                   capacity + (tdev->checksum_offload_enabled ? kTunVirtioHeaderSize : 0));
        if (nread < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return true;
            LOGE("TunDevice: receive failed for %s: %s", tdev->name, strerror(errno));
            return false;
        }
        if (nread == 0)
            return false;
        bytes += (uint32_t) nread;
        sbufSetLength(reader->scratch, (uint32_t) nread);
        if (tdev->checksum_offload_enabled)
        {
            if (nread < kTunVirtioHeaderSize)
            {
                tunOffloadCountReject(tdev, reader, kTunLinuxOffloadMalformed);
                continue;
            }
            uint8_t metadata[kTunVirtioHeaderSize];
            memoryCopy(metadata, sbufGetRawPtr(reader->scratch), sizeof(metadata));
            sbufShiftRight(reader->scratch, kTunVirtioHeaderSize);
            if (! tdev->gso_enabled && metadata[1] != 0)
            {
                tunOffloadCountReject(tdev, reader, kTunLinuxOffloadUnsupported);
                continue;
            }
            uint8_t                         *ip   = sbufGetMutablePtr(reader->scratch);
            tun_linux_offload_plan_t         plan = {0};
            const tun_linux_offload_reject_t reject =
                tunLinuxOffloadPreflight(metadata, ip, sbufGetLength(reader->scratch), tdev->mtu, &plan);
            if (reject != kTunLinuxOffloadAccept ||
                (tdev->trusted_checksums && ! tunLinuxOffloadTrustInput(metadata, ip, &plan)))
            {
                tunOffloadCountReject(
                    tdev, reader, reject != kTunLinuxOffloadAccept ? reject : kTunLinuxOffloadMalformed);
                continue;
            }
            if (plan.action == kTunLinuxOffloadSegment || plan.transport_assured ||
                (plan.action == kTunLinuxOffloadChecksum && tunOffloadCanDeferChecksum(ip, &plan)))
            {
                reader->pending_plan = plan;
                reader->pending      = true;
                if (plan.action == kTunLinuxOffloadSegment)
                    ++reader->gso_aggregates;
                else
                    ++reader->ordinary_records;
                continue;
            }
            if (plan.action == kTunLinuxOffloadChecksum)
            {
                tunLinuxOffloadCompleteChecksum(ip, &plan);
                ++reader->checksum_completions;
            }
            ++reader->ordinary_records;
        }
        /* Fragments share one synchronized, device-wide table. It owns detached
         * storage and never borrows any reader's worker-local pool. */
        sbuf_t *packet = reader->scratch;
        if (tdev->checksum_offload_enabled)
        {
            const uint32_t length = sbufGetLength(reader->scratch);
            packet                = bufferpoolGetBestFit(worker->buffer_pool, length, padding);
            memoryCopy(sbufGetMutablePtr(packet), sbufGetRawPtr(reader->scratch), length);
            sbufSetLength(packet, length);
        }
        else
            reader->scratch = NULL;
        tunReaderPreparePacket(lane, packet);
    }
    if (tunReaderPostPackets(lane) && reader->pending)
        discard tunReaderPostOffload(lane, worker);
    return true;
}

static void tunReaderOnReady(wio_t *io);
static void tunReaderRun(tun_worker_reader_t *lane, worker_t *worker)
{
    tun_reader_generation_t *generation = lane->generation;
    assert(worker->wid == lane->wid);
    if (! quiescenceGateEnter(&generation->gate))
    {
        tunReaderDetach(lane);
        return;
    }
    tun_device_t *tdev   = generation->device;
    bool          failed = false;
    if (lane->io == NULL)
    {
        wio_t *io = wioGet(worker->loop, lane->fd);
        if (io == NULL || wioGetFD(io) != lane->fd)
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
            weventSetUserData(lane->io, lane);
        }
    }
    if (! failed)
    {
        device_reader_burst_t burst;
        const bool            local_burst = deviceReaderSessionTryBeginBurst(generation->session, worker, &burst);
        failed = ! tunReaderDrain(lane, worker);
        /* This also settles a local token after capacity refusal, EAGAIN,
         * lifecycle closure or read failure while the generation is pinned. */
        if (local_burst)
            deviceReaderSessionEndBurst(&burst);
        if (atomicLoadExplicit(&lane->waiting, memory_order_acquire) || failed)
            wioDel(lane->io, WW_READ);
        else if (wioAdd(lane->io, tunReaderOnReady, WW_READ) != 0)
            failed = true;
    }
    tun_lifecycle_state_t failed_from;
    const bool            shutdown =
        failed && tunLifecycleTransitionToFailed(&tdev->lifecycle, &failed_from) && failed_from == kTunLifecycleUp;
    quiescenceGateLeave(&generation->gate);
    if (shutdown && ! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static void tunReaderOnReady(wio_t *io)
{
    tun_worker_reader_t *lane = weventGetUserdata(io);
    if (lane != NULL)
        tunReaderRun(lane, getCurrentWorker());
}

static void tunReaderMessage(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                  arg2;
    discard                  arg3;
    tun_worker_reader_t     *lane       = arg1;
    tun_reader_generation_t *generation = lane->generation;
    atomicStoreExplicit(&lane->scheduled, false, memory_order_release);
    tunReaderRun(lane, worker);
    tunReaderUnref(generation);
}

bool tunReaderOpen(tun_device_t *tdev)
{
    assert(tdev->reader == NULL && tdev->queue_count > 0);
    tun_reader_generation_t *generation =
        memoryAllocateZero(sizeof(*generation) + tdev->queue_count * sizeof(generation->lanes[0]));
    generation->device  = tdev;
    generation->session = tdev->reader_session;
    generation->count   = tdev->queue_count;
    atomicStoreRelaxed(&generation->references, 1);
    deviceReaderSessionRef(generation->session);
    quiescenceGateInit(&generation->gate);
    discard quiescenceGateOpen(&generation->gate);
    tdev->reader = generation;
    for (uint16_t i = 0; i < generation->count; ++i)
    {
        tun_worker_reader_t *lane = &generation->lanes[i];
        lane->generation          = generation;
        lane->wid                 = (wid_t) i;
        lane->fd                  = tdev->queue_fds[i];
    }
    atomicStoreExplicit(&tdev->reader_notify, (uintptr_t) generation, memory_order_release);
    if (tdev->read_event_callback == NULL)
        return true;
    /* Init is already in each worker FIFO; readiness is installed after it. */
    for (uint16_t i = 0; i < generation->count; ++i)
        if (! tunReaderSchedule(&generation->lanes[i], false))
            return false;
    return true;
}

void tunReaderCloseRequest(tun_device_t *tdev)
{
    tun_reader_generation_t *generation = tdev->reader;
    if (generation == NULL)
        return;
    quiescenceGateClose(&generation->gate);
    for (uint16_t i = 0; i < generation->count; ++i)
        discard tunReaderSchedule(&generation->lanes[i], true);
}

void tundeviceWorkerQuiesce(tun_device_t *tdev, wid_t wid)
{
    assert(currentThreadOwnsWorker(wid));
    tun_reader_generation_t *generation = tdev->reader;
    if (generation != NULL && wid < generation->count)
        tunReaderDetach(&generation->lanes[wid]);
}

void tunReaderCloseWait(tun_device_t *tdev)
{
    tun_reader_generation_t *generation = tdev->reader;
    if (generation == NULL)
        return;
    quiescenceGateWaitQuiesced(&generation->gate, quiescenceGateYieldThread, NULL);
    worker_t *worker = tryGetCurrentWorker();
    if (worker != NULL && worker->wid < generation->count)
        tunReaderDetach(&generation->lanes[worker->wid]);
    while (atomicLoadExplicit(&generation->attached, memory_order_acquire) != 0)
        quiescenceGateYieldThread(NULL);
    tun_offload_reader_t totals = {0};
    for (uint16_t i = 0; i < generation->count; ++i)
    {
        tun_worker_reader_t *lane = &generation->lanes[i];
        totals.ordinary_records += lane->offload.ordinary_records;
        totals.gso_aggregates += lane->offload.gso_aggregates;
        totals.checksum_completions += lane->offload.checksum_completions;
        totals.malformed_records += lane->offload.malformed_records;
        totals.unsupported_records += lane->offload.unsupported_records;
        totals.oversized_records += lane->offload.oversized_records;
        if (lane->offload.scratch != NULL)
            sbufDestroy(lane->offload.scratch);
        for (unsigned j = lane->pending_first; j < lane->pending_count; ++j)
            sbufDestroy(lane->pending_bufs[j]);
    }
    if (tdev->checksum_offload_enabled)
        LOGI("TunDevice: %s offload reader summary: ordinary=%llu aggregates=%llu generated=%llu reader-checksum=%llu "
             "malformed=%llu unsupported=%llu oversized=%llu intact=%llu",
             tdev->name,
             (unsigned long long) totals.ordinary_records,
             (unsigned long long) totals.gso_aggregates,
             (unsigned long long) atomicLoadRelaxed(&tdev->gso_generated_segments),
             (unsigned long long) totals.checksum_completions,
             (unsigned long long) totals.malformed_records,
             (unsigned long long) totals.unsupported_records,
             (unsigned long long) totals.oversized_records,
             (unsigned long long) atomicLoadRelaxed(&tdev->gso_intact_aggregates));
    atomicStoreExplicit(&tdev->reader_notify, (uintptr_t) NULL, memory_order_release);
    tdev->reader = NULL;
    tunReaderUnref(generation);
}

/* Both virtio modes require ordered admission and enough storage for any
 * ordinary work item. Configuration is one-time even if later GSO setup fails. */
bool tunConfigureWorkerOffload(tun_device_t *tdev)
{
    size_t         maximum_charge = sbufGetAllocationCharge(tdev->offload_scratch);
    buffer_pool_t *pool           = tdev->reader_buffer_pool;
    const uint16_t padding        = bufferpoolGetSmallBufferPadding(pool);
    const uint32_t lengths[]      = {tdev->mtu,
                                     min(bufferpoolGetSmallBufferSize(pool), (uint32_t) tdev->mtu),
                                     min(bufferpoolGetMediumBufferSize(pool), (uint32_t) tdev->mtu),
                                     min(bufferpoolGetLargeBufferSize(pool), (uint32_t) tdev->mtu)};
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
    {
        buffer_pool_fit_t fit;
        if (! bufferpoolQueryBestFit(pool, lengths[i], padding, &fit))
        {
            return false;
        }
        maximum_charge = max(maximum_charge, fit.allocation_charge);
    }
    if (maximum_charge + sizeof(tun_offload_work_t) > kTunOffloadPendingChargeLimit)
    {
        return false;
    }
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        tdev->offload_output_padding[wid] = bufferpoolGetSmallBufferPadding(getWorkerBufferPool(wid));
    }
    return deviceReaderSessionConfigureOutputBudget(
               tdev->reader_session, kTunOffloadPendingChargeLimit, kTunOffloadPendingPacketLimit) &&
           deviceReaderSessionEnableWorkerQueue(tdev->reader_session);
}

/* Best-fit choices change only at a tier's payload limit. Sampling those
 * limits and the MTU bounds every possible segment allocation, including tiers
 * with different padding. Later configurations may increase pool padding; the
 * worker then uses exact-sized storage if a tier exceeds this allowance. */
bool tunConfigureWorkerGso(tun_device_t *tdev)
{
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        buffer_pool_t *pool           = getWorkerBufferPool(wid);
        const uint16_t padding        = tdev->offload_output_padding[wid];
        const uint32_t lengths[]      = {1,
                                         tdev->mtu,
                                         min(bufferpoolGetSmallBufferSize(pool), (uint32_t) tdev->mtu),
                                         min(bufferpoolGetMediumBufferSize(pool), (uint32_t) tdev->mtu),
                                         min(bufferpoolGetLargeBufferSize(pool), (uint32_t) tdev->mtu)};
        size_t         maximum_charge = 0;
        for (unsigned int i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
        {
            buffer_pool_fit_t fit;
            if (! bufferpoolQueryBestFit(pool, lengths[i], padding, &fit))
            {
                return false;
            }
            maximum_charge = max(maximum_charge, fit.allocation_charge);
        }
        if (maximum_charge + sbufGetAllocationCharge(tdev->offload_scratch) + sizeof(tun_offload_work_t) >
            kTunOffloadPendingChargeLimit)
        {
            return false;
        }
        tdev->gso_output_charge[wid] = maximum_charge;
    }
    return true;
}
