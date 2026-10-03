#include "devices/device_flow_affinity.h"
#include "devices/device_reader_session.h"
#include "devices/device_writer_channel.h"
#include "devices/tun/tun_io_error.h"
#include "devices/tun/tun_lifecycle.h"
#ifdef OS_LINUX
#include "devices/tun/tun_linux_gso_limits.h"
#include "devices/tun/tun_linux_gso_write.h"
#include "devices/tun/tun_linux_offload.h"
#endif
#include "generic_pool.h"
#include "global_state.h"
#include "ipv4_packet_view.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"
#include "tun.h"
#include "tun_linux_internal.h"
#include "watomic.h"
#include "wchan.h"
#include "wplatform.h"
#include "wproc.h"
#include "wthread.h"
#include "wtime.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sys/ioctl.h>

#ifdef OS_LINUX
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#elif defined(OS_BSD)
#include <net/if.h>
#include <net/if_tun.h>
#else
#error "Unsupported OS"
#endif

#include "tun_linux_private.h"

static atomic_log_rate_limiter_t tun_write_packet_failure_log;

static void tunDeliverPacketAssured(void *device, sbuf_t *buf, wid_t wid, bool assured)
{
    tun_device_t *tdev = device;
#ifdef OS_LINUX
    if (UNLIKELY(tdev->trusted_checksums && ! assured &&
                 ! tunLinuxOffloadValidatePacket(sbufGetRawPtr(buf), sbufGetLength(buf))))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }
#else
    discard assured;
#endif
    tdev->read_event_callback(tdev, tdev->userdata, buf, wid);
}

void tunDeliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    tunDeliverPacketAssured(device, buf, wid, false);
}

// Hands whatever the drain cycle has already read to the reader session. Every
// exit from tunDrainPackets() goes through this, so a device error never
// strands packets that were read successfully before it.
static void tunFlushReadBatch(tun_device_t *tdev, sbuf_t **bufs, uint16_t queued_count)
{
    if (queued_count > 0)
    {
        deviceFlowAffinityPostBatch(tdev->reader_session, bufs, queued_count);
    }
}

#ifdef OS_LINUX
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

static void tunOffloadReaderInit(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    reader->scratch = tdev->offload_scratch;
    atomic_store_explicit(&tdev->gso_generated_segments, 0, memory_order_relaxed);
    atomic_store_explicit(&tdev->gso_intact_aggregates, 0, memory_order_relaxed);
    if (UNLIKELY(reader->scratch == NULL))
    {
        LOGF("TunDevice: offload reader started without its receive scratch");
        abortProgramNow(1);
    }
    sbufReset(reader->scratch);
    if (UNLIKELY(sbufGetLeftCapacity(reader->scratch) < kTunVirtioHeaderSize ||
                 sbufGetMaximumWriteableSize(reader->scratch) < kTunOffloadPacketStorageCapacity))
    {
        LOGF("TunDevice: published offload scratch violates required geometry");
        abortProgramNow(1);
    }
}

static void tunOffloadReaderCleanup(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    /* The device retains scratch through a later BringUp; the reader has
     * exclusive access only while its thread is running. */
    reader->scratch = NULL;
    LOGI("TunDevice: %s offload reader summary: ordinary=%llu aggregates=%llu generated=%llu reader-checksum=%llu "
         "malformed=%llu unsupported=%llu oversized=%llu intact=%llu",
         tdev->name,
         (unsigned long long) reader->ordinary_records,
         (unsigned long long) reader->gso_aggregates,
         (unsigned long long) atomic_load_explicit(&tdev->gso_generated_segments, memory_order_relaxed),
         (unsigned long long) reader->checksum_completions,
         (unsigned long long) reader->malformed_records,
         (unsigned long long) reader->unsupported_records,
         (unsigned long long) reader->oversized_records,
         (unsigned long long) atomic_load_explicit(&tdev->gso_intact_aggregates, memory_order_relaxed));
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
    assert(currentThreadIsEventWorkerWID(wid));
    buffer_pool_t *pool    = getWorkerBufferPool(wid);
    uint32_t       emitted = 0;
    /* The direct trusted TUN/PTC pair accepts assured TCPv4 aggregates intact.
     * Preflight has validated an exact, unfragmented packet <= UINT16_MAX.
     * Delivery uses the same selected worker and FIFO as segmented input. */
    tun_device_t *device = session->device;
    assert(work->plan.action != kTunLinuxOffloadSegment || (device->gso_enabled && work->output_charge > 0));
    const bool    intact_tcp_gso =
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
        tunDeliverPacketAssured(session->device, output, wid, work->plan.transport_assured);
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
        /* Active preflight either verified the aggregate or retained positive
         * metadata. Do not recheck an intentionally partial generated segment. */
        tunDeliverPacketAssured(session->device, output, wid, true);
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
static void tunOffloadPostPending(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    wid_t wid;
    if (UNLIKELY(! deviceFlowAffineWID(sbufGetRawPtr(reader->scratch), sbufGetLength(reader->scratch), &wid)))
    {
        LOGF("TunDevice: preflighted offload work has no flow identity");
        abortProgramNow(1);
    }
    const bool compact_checksum =
        reader->pending_plan.action == kTunLinuxOffloadChecksum && ! reader->pending_plan.transport_assured;
    buffer_pool_fit_t input_fit = {0};
    if (UNLIKELY(compact_checksum && ! bufferpoolQueryBestFit(tdev->reader_buffer_pool,
                                                              reader->pending_plan.ip_length,
                                                              bufferpoolGetSmallBufferPadding(tdev->reader_buffer_pool),
                                                              &input_fit)))
    {
        LOGF("TunDevice: ordinary checksum work has unrepresentable buffer geometry");
        abortProgramNow(1);
    }
    assert(reader->pending_plan.action != kTunLinuxOffloadSegment || tdev->gso_enabled);
    const size_t output_charge = compact_checksum || ! tdev->gso_enabled ? 0 : tdev->gso_output_charge[wid];
    const size_t input_charge =
        compact_checksum ? input_fit.allocation_charge : sbufGetAllocationCharge(reader->scratch);
    const size_t   charge        = input_charge + sizeof(tun_offload_work_t) + output_charge;
    const unsigned slots         = compact_checksum ? 1 : 2;
    reader->waiting_for_capacity = false;
    if (! deviceReaderSessionTryReserveWork(tdev->reader_session, charge, slots))
    {
        reader->waiting_for_capacity = true;
        return;
    }
    tun_offload_work_t *work = memoryAllocate(sizeof(*work));
    if (UNLIKELY(work == NULL))
    {
        deviceReaderSessionReleaseWork(tdev->reader_session, charge, slots);
        LOGF("TunDevice: failed to allocate reserved offload work metadata");
        abortProgramNow(1);
    }
    *work = (tun_offload_work_t) {.aggregate     = reader->scratch,
                                  .plan          = reader->pending_plan,
                                  .output_charge = output_charge,
                                  .padding       = tdev->offload_output_padding[wid]};
    if (compact_checksum)
    {
        work->aggregate = bufferpoolGetBestFit(tdev->reader_buffer_pool, work->plan.ip_length, input_fit.left_padding);
        if (UNLIKELY(work->aggregate == NULL || sbufGetAllocationCharge(work->aggregate) != input_charge))
        {
            LOGF("TunDevice: ordinary checksum storage violated its reservation");
            abortProgramNow(1);
        }
        memoryCopy(sbufGetMutablePtr(work->aggregate), sbufGetRawPtr(reader->scratch), work->plan.ip_length);
        sbufSetLength(work->aggregate, work->plan.ip_length);
    }
    else
    {
        const uint16_t padding =
            max(bufferpoolGetLargeBufferPadding(tdev->reader_buffer_pool), (uint16_t) kTunVirtioHeaderSize);
        reader->scratch = bufferpoolGetBestFit(tdev->reader_buffer_pool, kTunOffloadPacketStorageCapacity, padding);
        if (UNLIKELY(reader->scratch == NULL))
        {
            LOGF("TunDevice: failed to replace handed-off offload receive storage");
            abortProgramNow(1);
        }
        tdev->offload_scratch = reader->scratch;
    }
    reader->pending = false;
    discard deviceReaderSessionPostWork(
        tdev->reader_session, wid, work, tunOffloadWorkStep, tunOffloadWorkCleanup, charge, slots);
}

/* One bounded read drain. A GSO record stops this batch; the outer reader
 * loop admits the aggregate before polling or reading another record. */
static tun_drain_result_t tunDrainOffloadPackets(tun_device_t *tdev, tun_offload_reader_t *reader)
{
    sbuf_t            *bufs[kMaxReadDistributeQueueSize];
    uint16_t           queued_count  = 0;
    const uint32_t     output_budget = min((uint32_t) RAM_PROFILE, (uint32_t) kMaxReadDistributeQueueSize);
    tun_drain_result_t result        = kTunDrainAgain;

    for (uint32_t attempt = 0; attempt < RAM_PROFILE && queued_count < output_budget; ++attempt)
    {
        if (! tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            break;
        }

        /* Receive virtio metadata before the aligned IP start, in headroom.
         * Removing it restores the pool cursor without moving packet bytes. */
        sbufReset(reader->scratch);
        sbufShiftLeft(reader->scratch, kTunVirtioHeaderSize);
        uint8_t *record = sbufGetMutablePtr(reader->scratch);
        assert(sbufGetMaximumWriteableSize(reader->scratch) >= kTunVirtioHeaderSize + kTunOffloadPacketStorageCapacity);

        ssize_t nread;
        for (;;)
        {
            nread = read(tdev->handle, record, kTunVirtioHeaderSize + kTunOffloadPacketStorageCapacity);
            if (UNLIKELY(nread < 0 && errno == EINTR))
            {
                continue;
            }
            break;
        }
        if (UNLIKELY(nread == 0))
        {
            result = kTunDrainEndOfStream;
            break;
        }
        if (nread < 0)
        {
            const int saved_errno = errno;
            if (! tunIoErrnoIsTransient(saved_errno))
            {
                LOGE("TunDevice: unrecoverable offload read error on %s, errno %d (%s)",
                     tdev->name,
                     saved_errno,
                     strerror(saved_errno));
                result = kTunDrainDeviceError;
            }
            break;
        }
        if (UNLIKELY(nread < kTunVirtioHeaderSize))
        {
            tunOffloadCountReject(tdev, reader, kTunLinuxOffloadMalformed);
            continue;
        }

        uint8_t metadata[kTunVirtioHeaderSize];
        memoryCopy(metadata, record, sizeof(metadata));
        /* Preflight knows wire types, not the descriptor's negotiated mode. */
        if (! tdev->gso_enabled && metadata[1] != 0)
        {
            tunOffloadCountReject(tdev, reader, kTunLinuxOffloadUnsupported);
            continue;
        }
        sbufSetLength(reader->scratch, (uint32_t) nread);
        sbufShiftRight(reader->scratch, kTunVirtioHeaderSize);
        uint8_t       *ip        = sbufGetMutablePtr(reader->scratch);
        const uint32_t ip_length = sbufGetLength(reader->scratch);

        tun_linux_offload_plan_t         plan   = {0};
        const tun_linux_offload_reject_t reject = tunLinuxOffloadPreflight(metadata, ip, ip_length, tdev->mtu, &plan);
        if (UNLIKELY(reject != kTunLinuxOffloadAccept))
        {
            tunOffloadCountReject(tdev, reader, reject);
            continue;
        }
        if (UNLIKELY(tdev->trusted_checksums && ! tunLinuxOffloadTrustInput(metadata, ip, &plan)))
        {
            tunOffloadCountReject(tdev, reader, kTunLinuxOffloadMalformed);
            continue;
        }
        if (plan.action == kTunLinuxOffloadSegment || plan.transport_assured)
        {
            reader->pending_plan = plan;
            reader->pending      = true;
            if (plan.action == kTunLinuxOffloadSegment)
            {
                reader->gso_aggregates++;
            }
            else
            {
                reader->ordinary_records++;
            }
            break;
        }

        if (plan.action == kTunLinuxOffloadChecksum)
        {
            if (tunOffloadCanDeferChecksum(ip, &plan))
            {
                /* Publish older ordinary packets before this FIFO work item.
                 * Successful admission keeps this read drain batched; only
                 * capacity exhaustion retains the current record in scratch. */
                tunFlushReadBatch(tdev, bufs, queued_count);
                queued_count         = 0;
                reader->pending_plan = plan;
                reader->pending      = true;
                reader->ordinary_records++;
                tunOffloadPostPending(tdev, reader);
                if (reader->pending)
                {
                    break;
                }
                continue;
            }
            tunLinuxOffloadCompleteChecksum(ip, &plan);
            reader->checksum_completions++;
        }
        sbuf_t *output = bufferpoolGetBestFit(
            tdev->reader_buffer_pool, ip_length, bufferpoolGetSmallBufferPadding(tdev->reader_buffer_pool));
        if (UNLIKELY(output == NULL))
        {
            LOGE("TunDevice: failed to allocate ordinary offload-framed packet");
            result = kTunDrainDeviceError;
            break;
        }
        memoryCopy(sbufGetMutablePtr(output), ip, ip_length);
        sbufSetLength(output, ip_length);
        bufs[queued_count++] = output;
        reader->ordinary_records++;
    }

    if (queued_count > 0)
    {
        if (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            tunFlushReadBatch(tdev, bufs, queued_count);
        }
        else
        {
            for (uint16_t i = 0; i < queued_count; ++i)
            {
                bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[i]);
            }
        }
    }
    return result;
}
#endif

// Drains packets from the TUN device after POLLIN. Every accumulated buffer is
// handed to the reader session before returning, on every path.
static tun_drain_result_t tunDrainPackets(tun_device_t *tdev)
{
    uint16_t queued_count = 0;
    sbuf_t  *bufs[kMaxReadDistributeQueueSize];
    uint32_t read_size = tunDeviceMtu(tdev);

    for (uint32_t i = 0; i < RAM_PROFILE && queued_count < kMaxReadDistributeQueueSize; ++i)
    {
        bufs[queued_count] = bufferpoolGetSmallBuffer(tdev->reader_buffer_pool);
        bufs[queued_count] = sbufReserveSpace(bufs[queued_count], read_size);

        int nread;
        for (;;)
        {
            nread = (int) read(tdev->handle, sbufGetMutablePtr(bufs[queued_count]), read_size);
            if (UNLIKELY(nread < 0 && errno == EINTR))
            {
                continue;
            }
            break;
        }

        if (UNLIKELY(nread == 0))
        {
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            tunFlushReadBatch(tdev, bufs, queued_count);
            return kTunDrainEndOfStream;
        }

        if (nread < 0)
        {
            // errno is only meaningful right here: recycling the buffer and the
            // loggers below can both overwrite it.
            const int saved_errno = errno;
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);
            tunFlushReadBatch(tdev, bufs, queued_count);

            if (tunIoErrnoIsTransient(saved_errno))
            {
                // No more packets for now; end this cycle and go back to poll().
                return kTunDrainAgain;
            }

            /*
             * Anything else (EIO, EBADF, ENODEV, ENXIO, ...) means this handle
             * will not produce packets again. Returning "keep polling" here made
             * the reader spin on a permanently readable dead fd while every
             * packet vanished, so the loss is reported instead.
             */
            LOGE("TunDevice: unrecoverable read error on device %s, errno is %d (%s)",
                 tdev->name,
                 saved_errno,
                 strerror(saved_errno));
            return kTunDrainDeviceError;
        }

        if (TUN_LOG_EVERYTHING)
        {
            LOGD("TunDevice: read %d bytes from device %s", nread, tdev->name);
        }

        sbufSetLength(bufs[queued_count], nread);

        if (UNLIKELY(sbufGetLength(bufs[queued_count]) > read_size))
        {
            LOGE("TunDevice: ReadThread: read packet size %d exceeds device MTU %u",
                 sbufGetLength(bufs[queued_count]),
                 read_size);
            LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice 'device-mtu'");
            bufferpoolReuseBuffer(tdev->reader_buffer_pool, bufs[queued_count]);

            /*
             * A misconfigured MTU is fatal for the process, but this runs on the
             * device reader thread. Release everything this thread owns - the
             * oversized buffer above, plus the batch accumulated so far - and
             * report the loss so the read routine leaves through its normal exit
             * path. tundeviceNoteUnexpectedThreadExit() then publishes the
             * failure and owns the shutdown decision.
             */
            tunFlushReadBatch(tdev, bufs, queued_count);
            return kTunDrainDeviceError;
        }

        queued_count++;
    }

    // Distribute all accumulated packets in one batch
    tunFlushReadBatch(tdev, bufs, queued_count);

    return kTunDrainAgain;
}

static void tunLogReaderPollError(tun_device_t *tdev, short revents)
{
    int       socket_error = 0;
    socklen_t err_len      = sizeof(socket_error);
    getsockopt(tdev->handle, SOL_SOCKET, SO_ERROR, &socket_error, &err_len);
    LOGE("TunDevice: Exit read routine due to socket error event: %s%s%s, socket error: %d (%s)",
         (revents & POLLERR) ? "POLLERR " : "",
         (revents & POLLHUP) ? "POLLHUP " : "",
         (revents & POLLNVAL) ? "POLLNVAL " : "",
         socket_error,
         strerror(socket_error));
}

// Routine to read from TUN device
WTHREAD_ROUTINE(routineReadFromTun)
{
    tun_device_t *tdev = userdata;

    struct pollfd fds[3];
    fds[0].fd         = tdev->handle;
    fds[1].fd         = tdev->linux_pipe_fds[0];
    fds[0].events     = POLLIN;
    fds[1].events     = POLLIN;
    nfds_t poll_count = 2;

#ifdef OS_LINUX
    tun_offload_reader_t offload_reader = {0};
    if (tdev->checksum_offload_enabled)
    {
        tunOffloadReaderInit(tdev, &offload_reader);
        fds[2].fd  = deviceReaderSessionOutputWakeFd(tdev->reader_session);
        poll_count = 3;
    }
#endif

    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
#ifdef OS_LINUX
        if (tdev->checksum_offload_enabled && offload_reader.pending && ! offload_reader.waiting_for_capacity)
        {
            tunOffloadPostPending(tdev, &offload_reader);
            if (! offload_reader.pending || ! offload_reader.waiting_for_capacity)
            {
                continue;
            }
        }
        fds[0].events = tdev->checksum_offload_enabled && offload_reader.waiting_for_capacity ? 0 : POLLIN;
        if (tdev->checksum_offload_enabled)
        {
            fds[2].events = offload_reader.waiting_for_capacity ? POLLIN : 0;
        }
#endif
        int ret = poll(fds, poll_count, kTunReaderStopPollMs);

        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue; // Interrupted by signal, just retry
            }
            LOGE("TunDevice: Exit read routine due to poll failed with error %d (%s)", errno, strerror(errno));
            break;
        }

        if (ret == 0)
        {
            continue;
        }

        if (fds[1].revents & POLLIN)
        {
            char    drain_byte;
            ssize_t drain_res = read(tdev->linux_pipe_fds[0], &drain_byte, 1);
            discard drain_res;
            LOGW("TunDevice: Exit read routine due to pipe event");
            break;
        }

#ifdef OS_LINUX
        if (tdev->checksum_offload_enabled && offload_reader.waiting_for_capacity && (fds[2].revents & POLLIN))
        {
            deviceReaderSessionDrainOutputWake(tdev->reader_session);
            offload_reader.waiting_for_capacity = false;
            continue;
        }
        if (UNLIKELY(tdev->checksum_offload_enabled && (fds[2].revents & (POLLERR | POLLHUP | POLLNVAL))))
        {
            LOGE("TunDevice: offload output-capacity notification failed");
            break;
        }
#endif

        // Check for socket errors
        if (UNLIKELY((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0))
        {
            tunLogReaderPollError(tdev, fds[0].revents);
            break;
        }

        if (fds[0].revents & POLLIN)
        {
            tun_drain_result_t drain_res;
#ifdef OS_LINUX
            drain_res =
                tdev->checksum_offload_enabled ? tunDrainOffloadPackets(tdev, &offload_reader) : tunDrainPackets(tdev);
#else
            drain_res = tunDrainPackets(tdev);
#endif
            if (drain_res != kTunDrainAgain)
            {
                // The device is gone. Leaving the loop is what lets the thread
                // wrapper publish FAILED and request the orderly shutdown.
                LOGE("TunDevice: Exit read routine due to %s",
                     drain_res == kTunDrainEndOfStream ? "End Of File" : "an unrecoverable device read error");
                break;
            }
            continue;
        }

#ifdef OS_LINUX
        if (tdev->checksum_offload_enabled && offload_reader.waiting_for_capacity)
        {
            continue;
        }
#endif

        // If we get here, poll returned > 0 but none of our expected events occurred
        LOGE("TunDevice: Exit read routine due to unexpected poll events - fd[0].revents=0x%x, fd[1].revents=0x%x",
             fds[0].revents,
             fds[1].revents);
        break;
    }

#ifdef OS_LINUX
    if (tdev->checksum_offload_enabled)
    {
        tunOffloadReaderCleanup(tdev, &offload_reader);
    }
#endif
    return 0;
}

/* False ends the writer. A short packet write is never replayed as a suffix. */
static bool tunWriteResult(tun_device_t *tdev, ssize_t written, size_t expected, int write_errno)
{
    if (written > 0)
    {
        if (UNLIKELY((size_t) written != expected) &&
            atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
        {
            LOGW("TunDevice: discarded a packet after a short device write (%zd of %zu bytes)", written, expected);
        }
        return true;
    }
    if (UNLIKELY(written == 0))
    {
        LOGW("TunDevice: Exit write routine due to End Of File");
        return false;
    }
    if (tunIoErrnoIsTransient(write_errno) || tunWriteErrnoIsPacketLocal(write_errno))
    {
        if (atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
        {
            LOGW("TunDevice: discarded a packet, writing to device %s failed with errno %d (%s)",
                 tdev->name,
                 write_errno,
                 strerror(write_errno));
        }
        return true;
    }
    if (write_errno == EMSGSIZE)
    {
        LOGF("TunDevice: This is related to the MTU size, please set a correct value for TunDevice 'device-mtu'");
    }
    LOGE("TunDevice: Exit write routine due to an unrecoverable write error on device %s, errno %d (%s)",
         tdev->name,
         write_errno,
         strerror(write_errno));
    return false;
}

/* Consumes exactly this packet, including validation refusal and device failure. */
static bool tunWriteOrdinary(tun_device_t *tdev, sbuf_t *buf)
{
    if (UNLIKELY(tunDeviceMtu(tdev) < sbufGetLength(buf)))
    {
        if (atomicLogRateLimiterShouldLog(&tun_write_packet_failure_log, kTunPacketFailureLogIntervalMs))
        {
            LOGW("TunDevice: WriteThread: discarded a packet -> size %d exceeds device MTU %u",
                 sbufGetLength(buf),
                 tunDeviceMtu(tdev));
        }
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
        return true;
    }
    const size_t packet_length   = sbufGetLength(buf);
    const size_t expected_length = packet_length + (tdev->checksum_offload_enabled ? kTunVirtioHeaderSize : 0U);
    ssize_t      written;
    if (tdev->checksum_offload_enabled)
    {
        uint8_t metadata[kTunVirtioHeaderSize] = {0};
#ifdef OS_LINUX
        if (tdev->trusted_checksums &&
            ! tunLinuxOffloadEncodeWrite(sbufGetMutablePtr(buf), (uint32_t) packet_length, metadata))
        {
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            return true;
        }
#endif
        struct iovec iov[2] = {
            {.iov_base = metadata, .iov_len = sizeof(metadata)},
            {.iov_base = (void *) sbufGetRawPtr(buf), .iov_len = packet_length},
        };
        do
        {
            written = writev(tdev->handle, iov, 2);
        } while (written < 0 && errno == EINTR && tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)));
    }
    else
    {
        written = write(tdev->handle, sbufGetRawPtr(buf), packet_length);
    }
    const int write_errno = written < 0 ? errno : 0;
    bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
    return tunWriteResult(tdev, written, expected_length, write_errno);
}

WTHREAD_ROUTINE(routineWriteToTun)
{
    tun_device_t   *tdev    = userdata;
    struct wchan_s *channel = deviceWriterChannelGetConsumerChannel(&tdev->writer_channel);
#ifdef OS_LINUX
    bool    coalesce  = tdev->gso_enabled && tdev->trusted_checksums;
    sbuf_t *lookahead = NULL;
    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        sbuf_t  *batch[kTunWriteBatchPackets];
        unsigned count = 1;
        if (lookahead != NULL)
        {
            batch[0]  = lookahead;
            lookahead = NULL;
        }
        else if (! chanRecv(channel, &batch[0]))
            break;

        size_t charge = sbufGetAllocationCharge(batch[0]);
        while (coalesce && count < kTunWriteBatchPackets && charge < kTunWriteBatchCharge &&
               tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            bool    closed = false;
            sbuf_t *next;
            if (! chanTryRecv(channel, &next, &closed))
                break;
            const size_t next_charge = sbufGetAllocationCharge(next);
            if (next_charge > kTunWriteBatchCharge - charge)
            {
                lookahead = next;
                break;
            }
            batch[count++] = next;
            charge += next_charge;
        }
        unsigned offset       = 0;
        bool     keep_running = true;
        while (offset < count && tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            tun_linux_gso_write_t record;
            const unsigned        members =
                coalesce ? tunLinuxGsoBuildWrite(batch + offset, count - offset, tunDeviceMtu(tdev), &record) : 1;
            if (members == 1)
            {
                keep_running = tunWriteOrdinary(tdev, batch[offset++]);
            }
            else
            {
                ssize_t written;
                do
                {
                    written = writev(tdev->handle, record.iov, (int) record.count);
                } while (written < 0 && errno == EINTR && tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)));
                const int write_errno = written < 0 ? errno : 0;
                /* Linux tun_get_user rejects virtio metadata with EINVAL before
                 * injecting any skb. Only that definitive no-record failure is
                 * replayable; never replay a short/zero or ambiguous result.
                 * Keep originals intact and disable aggregation for this writer.
                 * See Linux v5.15 drivers/net/tun.c:virtio_net_hdr_to_skb. */
                if (written < 0 && write_errno == EINVAL)
                {
                    coalesce = false;
                    LOGW("TunDevice: %s rejected TCP GSO output; using ordinary packet writes", tdev->name);
                    continue;
                }
                for (unsigned i = 0; i < members; ++i)
                    bufferpoolReuseBuffer(tdev->writer_buffer_pool, batch[offset++]);
                keep_running = tunWriteResult(tdev, written, record.length, write_errno);
            }
            if (! keep_running)
                break;
        }
        /* Stop and permanent failures settle all local ownership here. The
         * coordinator drains only records still in the channel after join. */
        while (offset < count)
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, batch[offset++]);
        if (! keep_running)
            break;
    }
    if (lookahead != NULL)
        bufferpoolReuseBuffer(tdev->writer_buffer_pool, lookahead);
#else
    while (tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
    {
        sbuf_t *buf;
        if (! chanRecv(channel, &buf))
            break;
        if (! tunLifecycleIsActive(tunLifecycleLoad(&tdev->lifecycle)))
        {
            bufferpoolReuseBuffer(tdev->writer_buffer_pool, buf);
            break;
        }
        if (! tunWriteOrdinary(tdev, buf))
            break;
    }
#endif
    return 0;
}

/* Failure-only TLS sampler. Full is ordinary bounded overload and deliberately
 * silent; Down/Closed keep sparse lifecycle evidence without a shared limiter. */
static bool tundeviceShouldLogRefusal(void)
{
    static thread_local uint32_t refusal_count;
    const uint32_t               ordinal = ++refusal_count;

    return ordinal == 1 || (ordinal & (ordinal - 1U)) == 0;
}

// Write to TUN device
bool tundeviceWrite(tun_device_t *tdev, sbuf_t *buf)
{
#if ! defined(OS_BSD)
    assert(sbufGetLength(buf) > sizeof(struct iphdr));
#endif

    switch (deviceWriterChannelTrySend(&tdev->writer_channel, buf))
    {
    case kDeviceWriterSendOk:
        return true;
    case kDeviceWriterSendDown:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: write failed, device is down");
        }
        return false;
    case kDeviceWriterSendClosed:
        if (tundeviceShouldLogRefusal())
        {
            LOGE("TunDevice: write failed, channel was closed");
        }
        return false;
    case kDeviceWriterSendFull:
        return false;
    }

    return false;
}

#ifdef OS_LINUX
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

#endif
