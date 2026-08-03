#include "structure.h"

#include "loggers/network_logger.h"
#include "tls_client_hello.h"
#include "tricks/protoswap/trick.h"

enum
{
    kIpManipulatorTlsCaptureTimeoutMs      = 1500,
    kIpManipulatorTlsPrestartTimeoutMs     = 50,
    kIpManipulatorTlsPrestartMinPayloadLen = 128,
    kIpManipulatorTlsCaptureMaxRecordLen   = 16384,
    kIpManipulatorEgressWarningIntervalMs  = 5000
};

typedef struct ipmanipulator_tcp_packet_info_s
{
    const uint8_t *packet;
    const uint8_t *payload;
    uint32_t       seq;
    uint32_t       src_addr;
    uint32_t       dst_addr;
    uint16_t       ip_total_len;
    uint16_t       ip_header_len;
    uint16_t       tcp_header_len;
    uint16_t       headers_len;
    uint16_t       tcp_payload_len;
    uint16_t       src_port;
    uint16_t       dst_port;
} ipmanipulator_tcp_packet_info_t;

bool ipmanipulatorShouldLogEgressWarning(ipmanipulator_tstate_t *state)
{
    uint64_t now_ms   = max(getTickMS(), 1ULL);
    uint64_t observed = atomicLoadU64Relaxed(&state->egress_last_warning_ms);

    for (;;)
    {
        if (observed != 0 && now_ms >= observed && now_ms - observed < kIpManipulatorEgressWarningIntervalMs)
        {
            return false;
        }

        if (atomicCompareExchangeU64(&state->egress_last_warning_ms, &observed, now_ms))
        {
            return true;
        }
    }
}

typedef struct ipmanipulator_tls_clienthello_start_s
{
    ipmanipulator_tcp_packet_info_t tcp;
    uint32_t                        tls_record_total_len;
} ipmanipulator_tls_clienthello_start_t;

typedef enum ipmanipulator_tls_clienthello_start_status_e
{
    kIpManipulatorTlsClientHelloStartMiss = 0,
    kIpManipulatorTlsClientHelloStartPartial,
    kIpManipulatorTlsClientHelloStartComplete,
    kIpManipulatorTlsClientHelloStartFragmented,
    kIpManipulatorTlsClientHelloStartUnsupported
} ipmanipulator_tls_clienthello_start_status_t;

uint8_t ipmanipulatorResolveTransportProtocol(const ipmanipulator_tstate_t *state, uint8_t packet_protocol)
{
    /*
     * Mapped values must win over literal protocol numbers. Creation rejects
     * literal TCP/UDP replacements and collisions between TCP and UDP maps, so
     * each configured wire value has one inverse.
     */
    if (packet_protocol == state->trick_proto_swap_tcp_number)
    {
        return IPPROTO_TCP;
    }

    if (packet_protocol == state->trick_proto_swap_udp_number)
    {
        return IPPROTO_UDP;
    }

    if (packet_protocol == IPPROTO_TCP)
    {
        return IPPROTO_TCP;
    }

    if (packet_protocol == IPPROTO_UDP)
    {
        return IPPROTO_UDP;
    }

    return 0;
}

typedef struct ipmanipulator_tls_prestart_timeout_msg_s
{
    uint32_t slot_index;
    uint32_t generation;
} ipmanipulator_tls_prestart_timeout_msg_t;

static const char *ipmanipulatorTlsCaptureKindName(ipmanipulator_tls_capture_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorTlsCaptureKindFirstSni:
        return "first-sni";
    case kIpManipulatorTlsCaptureKindSmuggleSni:
        return "smuggle-sni";
    case kIpManipulatorTlsCaptureKindEchSni:
        return "ech-sni-trick";
    default:
        return "unknown";
    }
}

static bool ipmanipulatorTlsCaptureKindAllowsPrestart(ipmanipulator_tls_capture_kind_e kind)
{
    /*
     * ECH deliberately never speculates: a capture only starts on a packet that
     * already carries a recognizable ClientHello record beginning.
     */
    return kind == kIpManipulatorTlsCaptureKindSmuggleSni;
}

static void ipmanipulatorNotifyCaptureOwnerFailed(tunnel_t *t, const ipmanipulator_tls_capture_slot_t *slot)
{
    switch (slot->kind)
    {
    case kIpManipulatorTlsCaptureKindSmuggleSni:
        smugglesnitrickSetFlowPassthrough(t, slot->src_addr, slot->dst_addr, slot->src_port, slot->dst_port);
        return;
    case kIpManipulatorTlsCaptureKindEchSni:
        echsnitrickSetFlowPassthrough(
            t, slot->src_addr, slot->dst_addr, slot->src_port, slot->dst_port, slot->owner_generation);
        return;
    default:
        return;
    }
}

static void ipmanipulatorResetCapturedSlot(ipmanipulator_tls_capture_slot_t *slot)
{
    uint32_t gen = slot->generation + 1;
    if (gen == 0)
    {
        gen = 1;
    }
    memoryZero(slot, sizeof(*slot));
    slot->generation = gen;
}

static void ipmanipulatorTakeCapturedSlot(ipmanipulator_tls_capture_slot_t *dest, ipmanipulator_tls_capture_slot_t *src)
{
    *dest = *src;
    ipmanipulatorResetCapturedSlot(src);
}

static void ipmanipulatorResetPrestartSlot(ipmanipulator_tls_prestart_slot_t *slot)
{
    memoryZero(slot, sizeof(*slot));
}

static void ipmanipulatorTakePrestartSlot(ipmanipulator_tls_prestart_slot_t *dest,
                                          ipmanipulator_tls_prestart_slot_t *src)
{
    *dest = *src;
    ipmanipulatorResetPrestartSlot(src);
}

static void ipmanipulatorDestroyCapturedPacketEntry(ipmanipulator_captured_packet_t *entry)
{
    if (entry->buf != NULL)
    {
        sbufDestroy(entry->buf);
    }

    entry->line = NULL;
    entry->buf  = NULL;
}

static void ipmanipulatorReplayCapturedPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;

    tunnel_t *t   = arg1;
    line_t   *l   = arg2;
    sbuf_t   *buf = arg3;

    if (lineIsAlive(l))
    {
        lineSetRecalculateChecksum(l, true);
        ipmanipulatorSendUpstreamFinal(t, l, buf);
    }
    else
    {
        lineReuseBuffer(l, buf);
    }

    lineUnlock(l);
}

static void ipmanipulatorRecycleCapturedPacketOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    line_t *l   = arg1;
    sbuf_t *buf = arg2;

    lineReuseBuffer(l, buf);
    lineUnlock(l);
}

static void ipmanipulatorCleanupPacketBuffer(line_t *l, sbuf_t *buf)
{
    if (buf == NULL)
    {
        return;
    }

    // Only the line's own worker may return the packet to its pool; anyone else
    // (another worker, lwIP, a device thread) destroys the standalone buffer.
    if (lineIsOnCurrentEventWorker(l))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    sbufDestroy(buf);
}

static void ipmanipulatorCleanupCapturedPacketNormal(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    line_t *l   = arg2;
    sbuf_t *buf = arg3;

    ipmanipulatorCleanupPacketBuffer(l, buf);
    lineUnlock(l);
}

static void ipmanipulatorCleanupCapturedPacketReuse(void *arg1, void *arg2, void *arg3)
{
    discard arg3;

    line_t *l   = arg1;
    sbuf_t *buf = arg2;

    ipmanipulatorCleanupPacketBuffer(l, buf);
    lineUnlock(l);
}

static void ipmanipulatorScheduleCapturedPacketNormal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (lineIsOnCurrentEventWorker(l))
    {
        lineSetRecalculateChecksum(l, true);
        ipmanipulatorSendUpstreamFinal(t, l, buf);
        return;
    }

    lineLock(l);
    sendWorkerMessageForceQueueWithCleanup(lineGetWID(l),
                                           (WorkerMessageCallback) ipmanipulatorReplayCapturedPacketOnWorker,
                                           ipmanipulatorCleanupCapturedPacketNormal,
                                           t,
                                           l,
                                           buf);
}

static void ipmanipulatorScheduleCapturedPacketReuse(line_t *l, sbuf_t *buf)
{
    if (lineIsOnCurrentEventWorker(l))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    lineLock(l);
    sendWorkerMessageForceQueueWithCleanup(lineGetWID(l),
                                           (WorkerMessageCallback) ipmanipulatorRecycleCapturedPacketOnWorker,
                                           ipmanipulatorCleanupCapturedPacketReuse,
                                           l,
                                           buf,
                                           NULL);
}

static void ipmanipulatorReleasePrestartPacketsNormal(tunnel_t *t, ipmanipulator_tls_prestart_slot_t *slot)
{
    if (slot == NULL)
    {
        return;
    }

    if (slot->kind == kIpManipulatorTlsCaptureKindSmuggleSni)
    {
        smugglesnitrickSetFlowPassthrough(t, slot->src_addr, slot->dst_addr, slot->src_port, slot->dst_port);
    }

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        ipmanipulator_captured_packet_t *prestart_entry = &slot->captured_packets[i];

        if (prestart_entry->line != NULL && prestart_entry->buf != NULL)
        {
            ipmanipulatorScheduleCapturedPacketNormal(t, prestart_entry->line, prestart_entry->buf);
        }

        prestart_entry->line = NULL;
        prestart_entry->buf  = NULL;
    }

    ipmanipulatorResetPrestartSlot(slot);
}

static void ipmanipulatorReleasePendingPrestartOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t                                 *t            = arg1;
    ipmanipulator_tls_prestart_timeout_msg_t *msg          = arg2;
    ipmanipulator_tstate_t                   *state        = tunnelGetState(t);
    ipmanipulator_tls_prestart_slot_t         release_slot = {0};

    mutexLock(&state->tls_capture_mutex);

    if (msg->slot_index < state->tls_prestart_slots_count)
    {
        ipmanipulator_tls_prestart_slot_t *slot = &state->tls_prestart_slots[msg->slot_index];

        if (slot->active && slot->generation == msg->generation &&
            getTickMS() - slot->last_update_ms >= kIpManipulatorTlsPrestartTimeoutMs)
        {
            ipmanipulatorTakePrestartSlot(&release_slot, slot);
        }
    }

    mutexUnlock(&state->tls_capture_mutex);

    if (release_slot.active)
    {
        ipmanipulatorReleasePrestartPacketsNormal(t, &release_slot);
    }

    memoryFree(msg);
}

static void ipmanipulatorCleanupPendingPrestartMessage(void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg3;

    memoryFree(arg2);
}

static void ipmanipulatorSchedulePrestartTimeout(tunnel_t *t, uint32_t slot_index, uint32_t generation)
{
    ipmanipulator_tls_prestart_timeout_msg_t *msg = memoryAllocate(sizeof(*msg));
    *msg                                          = (ipmanipulator_tls_prestart_timeout_msg_t) {
                                                 .slot_index = slot_index,
                                                 .generation = generation,
    };

    sendWorkerMessageTimedWithCleanup(getCurrentEventWorkerWID(),
                                      (WorkerMessageCallback) ipmanipulatorReleasePendingPrestartOnWorker,
                                      ipmanipulatorCleanupPendingPrestartMessage,
                                      kIpManipulatorTlsPrestartTimeoutMs,
                                      t,
                                      msg,
                                      NULL);
}

void ipmanipulatorReleasePendingCaptureOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t                                *t            = arg1;
    ipmanipulator_tls_capture_timeout_msg_t *msg          = arg2;
    ipmanipulator_tstate_t                  *state        = tunnelGetState(t);
    ipmanipulator_tls_capture_slot_t         release_slot = {0};

    mutexLock(&state->tls_capture_mutex);

    if (msg->slot_index < state->tls_capture_slots_count)
    {
        ipmanipulator_tls_capture_slot_t *slot = &state->tls_capture_slots[msg->slot_index];

        if (slot->active && slot->generation == msg->generation &&
            getTickMS() - slot->last_update_ms >= kIpManipulatorTlsCaptureTimeoutMs)
        {
            ipmanipulatorTakeCapturedSlot(&release_slot, slot);
        }
    }

    mutexUnlock(&state->tls_capture_mutex);

    if (release_slot.active)
    {
        ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
    }

    memoryFree(msg);
}

static void ipmanipulatorCleanupPendingCaptureMessage(void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg3;

    memoryFree(arg2);
}

static void ipmanipulatorScheduleCaptureTimeout(tunnel_t *t, uint32_t slot_index, uint32_t generation)
{
    if (getWorkersCount() == 0 || GSTATE.workers == NULL)
    {
        return;
    }

    ipmanipulator_tls_capture_timeout_msg_t *msg = memoryAllocate(sizeof(*msg));
    *msg                                         = (ipmanipulator_tls_capture_timeout_msg_t) {
                                                .slot_index = slot_index,
                                                .generation = generation,
    };

    sendWorkerMessageTimedWithCleanup(getCurrentEventWorkerWID(),
                                      (WorkerMessageCallback) ipmanipulatorReleasePendingCaptureOnWorker,
                                      ipmanipulatorCleanupPendingCaptureMessage,
                                      kIpManipulatorTlsCaptureTimeoutMs,
                                      t,
                                      msg,
                                      NULL);
}

void ipmanipulatorReleaseCapturedPacketsNormal(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot)
{
    if (slot == NULL)
    {
        return;
    }

    ipmanipulatorNotifyCaptureOwnerFailed(t, slot);

    if (slot->assembled_packet != NULL)
    {
        sbufDestroy(slot->assembled_packet);
        slot->assembled_packet = NULL;
    }

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        ipmanipulator_captured_packet_t *entry = &slot->captured_packets[i];

        if (entry->line != NULL && entry->buf != NULL)
        {
            ipmanipulatorScheduleCapturedPacketNormal(t, entry->line, entry->buf);
        }

        entry->line = NULL;
        entry->buf  = NULL;
    }

    slot->captured_packets_count = 0;
    slot->active                 = false;
}

bool ipmanipulatorTakeMatchingCaptureSlot(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                          uint16_t dst_port, ipmanipulator_tls_capture_kind_e kind,
                                          uint64_t owner_generation, bool match_any_generation,
                                          ipmanipulator_tls_capture_slot_t *out_slot)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (out_slot == NULL)
    {
        return false;
    }

    memoryZero(out_slot, sizeof(*out_slot));

    if (state->tls_capture_slots == NULL)
    {
        return false;
    }

    /*
     * Detach under tls_capture_mutex only. The caller forwards, recycles or
     * disposes the detached slot after this function returns, so no inter-tunnel
     * callback ever runs while the capture mutex is held.
     */
    mutexLock(&state->tls_capture_mutex);

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        ipmanipulator_tls_capture_slot_t *slot = &state->tls_capture_slots[i];

        if (! slot->active || slot->kind != kind)
        {
            continue;
        }

        if (! match_any_generation && slot->owner_generation != owner_generation)
        {
            continue;
        }

        /* The normalized tuple matches in either direction. */
        if ((slot->src_addr == src_addr && slot->dst_addr == dst_addr && slot->src_port == src_port &&
             slot->dst_port == dst_port) ||
            (slot->src_addr == dst_addr && slot->dst_addr == src_addr && slot->src_port == dst_port &&
             slot->dst_port == src_port))
        {
            ipmanipulatorTakeCapturedSlot(out_slot, slot);
            break;
        }
    }

    mutexUnlock(&state->tls_capture_mutex);
    return out_slot->active;
}

bool ipmanipulatorFlushMatchingCaptureSlot(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                           uint16_t dst_port, ipmanipulator_tls_capture_kind_e kind)
{
    ipmanipulator_tls_capture_slot_t release_slot = {0};

    if (! ipmanipulatorTakeMatchingCaptureSlot(t, src_addr, dst_addr, src_port, dst_port, kind, 0, true, &release_slot))
    {
        return false;
    }

    ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
    return true;
}

void ipmanipulatorDestroyCapturedTlsPackets(ipmanipulator_tls_capture_slot_t *slot)
{
    if (slot == NULL)
    {
        return;
    }

    if (slot->assembled_packet != NULL)
    {
        sbufDestroy(slot->assembled_packet);
        slot->assembled_packet = NULL;
    }

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        ipmanipulatorDestroyCapturedPacketEntry(&slot->captured_packets[i]);
    }

    slot->captured_packets_count = 0;
    slot->active                 = false;
}

void ipmanipulatorRecycleCapturedTlsPackets(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot)
{
    discard t;

    if (slot == NULL)
    {
        return;
    }

    if (slot->assembled_packet != NULL)
    {
        sbufDestroy(slot->assembled_packet);
        slot->assembled_packet = NULL;
    }

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        ipmanipulator_captured_packet_t *entry = &slot->captured_packets[i];

        if (entry->line != NULL && entry->buf != NULL)
        {
            ipmanipulatorScheduleCapturedPacketReuse(entry->line, entry->buf);
        }

        entry->line = NULL;
        entry->buf  = NULL;
    }

    slot->captured_packets_count = 0;
    slot->active                 = false;
}

static bool ipmanipulatorParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                            ipmanipulator_tcp_packet_info_t *info)
{
    ipv4_packet_view_t packet_view = {0};
    if (! ipv4packetviewParseTcp(packet, packet_length, &packet_view) || packet_view.fragmented)
    {
        return false;
    }

    *info = (ipmanipulator_tcp_packet_info_t) {
        .packet          = packet,
        .payload         = packet + packet_view.payload_offset,
        .seq             = packet_view.tcp_sequence,
        .src_addr        = packet_view.source_address,
        .dst_addr        = packet_view.destination_address,
        .ip_total_len    = packet_view.ip_total_length,
        .ip_header_len   = packet_view.ip_header_length,
        .tcp_header_len  = packet_view.transport_header_length,
        .headers_len     = packet_view.payload_offset,
        .tcp_payload_len = packet_view.payload_length,
        .src_port        = packet_view.source_port,
        .dst_port        = packet_view.destination_port,
    };

    return true;
}

static ipmanipulator_tls_clienthello_start_status_t ipmanipulatorInspectTlsClientHelloPrefix(
    const uint8_t *payload, uint32_t payload_len, uint32_t *tls_record_total_len_out)
{
    *tls_record_total_len_out = 0;

    if (payload_len == 0 || payload[0] != 0x16)
    {
        return kIpManipulatorTlsClientHelloStartMiss;
    }

    if ((payload_len >= 2U && payload[1] != 0x03) || (payload_len >= 3U && payload[2] > 0x03) ||
        (payload_len >= 6U && payload[5] != 0x01))
    {
        return kIpManipulatorTlsClientHelloStartMiss;
    }

    uint16_t tls_record_len = 0;
    if (payload_len >= 5U)
    {
        tls_record_len = GET_BE16(payload + 3);

        if (tls_record_len < 4U || 5U + (uint32_t) tls_record_len > kIpManipulatorTlsCaptureMaxRecordLen)
        {
            return kIpManipulatorTlsClientHelloStartUnsupported;
        }

        *tls_record_total_len_out = 5U + (uint32_t) tls_record_len;
    }

    if (payload_len < 9U)
    {
        return kIpManipulatorTlsClientHelloStartPartial;
    }

    uint32_t client_hello_len = GET_BE24(payload + 6);

    if (client_hello_len < 34)
    {
        return kIpManipulatorTlsClientHelloStartUnsupported;
    }

    if (client_hello_len + 4U > tls_record_len)
    {
        LOGD("IpManipulator: TLS ClientHello starts in this packet but spans multiple TLS records "
             "(record=%u, client_hello=%u); TLS capture currently only assembles one TLS record",
             (unsigned int) tls_record_len,
             client_hello_len);
        return kIpManipulatorTlsClientHelloStartUnsupported;
    }

    return *tls_record_total_len_out <= payload_len ? kIpManipulatorTlsClientHelloStartComplete
                                                    : kIpManipulatorTlsClientHelloStartFragmented;
}

static ipmanipulator_tls_clienthello_start_status_t ipmanipulatorInspectTlsClientHelloStart(
    const uint8_t *packet, uint32_t packet_length, ipmanipulator_tls_clienthello_start_t *start)
{
    ipmanipulator_tcp_packet_info_t tcp = {0};

    if (! ipmanipulatorParseTcpPacketInfo(packet, packet_length, &tcp))
    {
        return kIpManipulatorTlsClientHelloStartMiss;
    }

    uint32_t                                     tls_record_total_len = 0;
    ipmanipulator_tls_clienthello_start_status_t status =
        ipmanipulatorInspectTlsClientHelloPrefix(tcp.payload, tcp.tcp_payload_len, &tls_record_total_len);

    *start = (ipmanipulator_tls_clienthello_start_t) {
        .tcp                  = tcp,
        .tls_record_total_len = tls_record_total_len,
    };

    return status;
}

static bool ipmanipulatorTlsCaptureSlotMatches(const ipmanipulator_tls_capture_slot_t *slot,
                                               const ipmanipulator_tcp_packet_info_t  *info,
                                               ipmanipulator_tls_capture_kind_e kind, uint64_t owner_generation)
{
    return slot->active && slot->kind == kind && slot->owner_generation == owner_generation &&
           slot->src_addr == info->src_addr && slot->dst_addr == info->dst_addr && slot->src_port == info->src_port &&
           slot->dst_port == info->dst_port;
}

static bool ipmanipulatorTlsPrestartSlotMatches(const ipmanipulator_tls_prestart_slot_t *slot,
                                                const ipmanipulator_tcp_packet_info_t   *info,
                                                ipmanipulator_tls_capture_kind_e         kind)
{
    return slot->active && slot->kind == kind && slot->src_addr == info->src_addr && slot->dst_addr == info->dst_addr &&
           slot->src_port == info->src_port && slot->dst_port == info->dst_port;
}

static bool ipmanipulatorPrestartSlotContainsSeq(const ipmanipulator_tls_prestart_slot_t *slot, uint32_t seq)
{
    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        const ipmanipulator_captured_packet_t *entry = &slot->captured_packets[i];
        ipmanipulator_tcp_packet_info_t        info  = {0};

        if (entry->buf != NULL &&
            ipmanipulatorParseTcpPacketInfo(
                (const uint8_t *) sbufGetRawPtr(entry->buf), sbufGetLength(entry->buf), &info) &&
            info.seq == seq)
        {
            return true;
        }
    }

    return false;
}

static bool ipmanipulatorAppendPacketToPrestartSlot(ipmanipulator_tls_prestart_slot_t *slot, line_t *l, sbuf_t *buf,
                                                    const ipmanipulator_tcp_packet_info_t *info)
{
    if (slot == NULL || ! slot->active)
    {
        return false;
    }

    if (slot->captured_packets_count >= kIpManipulatorTlsCaptureMaxPackets ||
        ipmanipulatorPrestartSlotContainsSeq(slot, info->seq))
    {
        return false;
    }

    slot->captured_packets[slot->captured_packets_count++] = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
    slot->last_update_ms                                   = getTickMS();
    slot->generation += 1;
    if (slot->generation == 0)
    {
        slot->generation = 1;
    }

    return true;
}

static void ipmanipulatorDestroyPrestartPackets(ipmanipulator_tls_prestart_slot_t *slot)
{
    if (slot == NULL)
    {
        return;
    }

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        ipmanipulatorDestroyCapturedPacketEntry(&slot->captured_packets[i]);
    }

    ipmanipulatorResetPrestartSlot(slot);
}

static sbuf_t *ipmanipulatorCreateStandalonePacketBuffer(const sbuf_t *template_buf, uint32_t packet_len)
{
    sbuf_t *buf = sbufCreateWithPadding(packet_len, sbufGetLeftPadding(template_buf));
    sbufSetLength(buf, packet_len);
    return buf;
}

static bool ipmanipulatorAppendPacketToCaptureSlot(ipmanipulator_tls_capture_slot_t *slot, line_t *l, sbuf_t *buf,
                                                   const ipmanipulator_tcp_packet_info_t *info, bool *complete)
{
    if (slot == NULL || ! slot->active || slot->assembled_packet == NULL || complete == NULL)
    {
        return false;
    }

    if (info->seq != slot->next_seq || info->tcp_payload_len == 0)
    {
        return false;
    }

    if (slot->captured_packets_count >= kIpManipulatorTlsCaptureMaxPackets)
    {
        return false;
    }

    if (slot->tls_record_total_len != 0 && slot->tls_record_captured_len >= slot->tls_record_total_len)
    {
        return false;
    }

    uint32_t new_payload_len = slot->captured_payload_len + info->tcp_payload_len;
    uint32_t prefix_len      = min(new_payload_len, 9U);
    uint8_t  prefix[9];
    uint32_t old_prefix_len = min(slot->captured_payload_len, prefix_len);

    if (old_prefix_len > 0)
    {
        memoryCopy(prefix, (const uint8_t *) sbufGetRawPtr(slot->assembled_packet) + slot->headers_len, old_prefix_len);
    }
    if (old_prefix_len < prefix_len)
    {
        memoryCopy(prefix + old_prefix_len, info->payload, prefix_len - old_prefix_len);
    }

    uint32_t                                     inferred_total_len = 0;
    ipmanipulator_tls_clienthello_start_status_t prefix_status =
        ipmanipulatorInspectTlsClientHelloPrefix(prefix, prefix_len, &inferred_total_len);

    if (prefix_status == kIpManipulatorTlsClientHelloStartMiss ||
        prefix_status == kIpManipulatorTlsClientHelloStartUnsupported ||
        (slot->tls_record_total_len != 0 && inferred_total_len != 0 &&
         slot->tls_record_total_len != inferred_total_len))
    {
        return false;
    }

    uint32_t tls_record_total_len = slot->tls_record_total_len != 0 ? slot->tls_record_total_len : inferred_total_len;

    if (new_payload_len > (uint32_t) UINT16_MAX - slot->headers_len)
    {
        return false;
    }

    if (tls_record_total_len != 0 && new_payload_len > tls_record_total_len)
    {
        LOGD("IpManipulator: fragmented TLS ClientHello completed with %u extra TCP payload bytes in the same segment",
             new_payload_len - tls_record_total_len);
    }

    uint32_t new_packet_len = slot->headers_len + new_payload_len;
    slot->assembled_packet  = sbufReserveSpace(slot->assembled_packet, new_packet_len);

    uint8_t *dest = sbufGetMutablePtr(slot->assembled_packet) + slot->headers_len + slot->captured_payload_len;
    memoryCopyLarge(dest, info->payload, info->tcp_payload_len);

    slot->captured_packets[slot->captured_packets_count++] = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
    slot->captured_payload_len                             = new_payload_len;
    slot->tls_record_total_len                             = tls_record_total_len;
    slot->tls_record_captured_len =
        tls_record_total_len == 0 ? new_payload_len : min(new_payload_len, tls_record_total_len);
    slot->next_seq += info->tcp_payload_len;
    slot->last_update_ms = getTickMS();

    LOGD("IpManipulator: captured TLS ClientHello fragment payload=%u captured=%u/%u packets=%u",
         (unsigned int) info->tcp_payload_len,
         slot->tls_record_captured_len,
         slot->tls_record_total_len,
         (unsigned int) slot->captured_packets_count);

    if (slot->tls_record_total_len != 0 && slot->tls_record_captured_len == slot->tls_record_total_len)
    {
        sbufSetLength(slot->assembled_packet, slot->headers_len + slot->captured_payload_len);
        IPH_LEN_SET((struct ip_hdr *) sbufGetMutablePtr(slot->assembled_packet),
                    lwip_htons((uint16_t) (slot->headers_len + slot->captured_payload_len)));
        *complete = true;
    }
    else
    {
        sbufSetLength(slot->assembled_packet, slot->headers_len + slot->captured_payload_len);
        IPH_LEN_SET((struct ip_hdr *) sbufGetMutablePtr(slot->assembled_packet),
                    lwip_htons((uint16_t) (slot->headers_len + slot->captured_payload_len)));
        *complete = false;
    }

    return true;
}

static bool ipmanipulatorCaptureSlotHasExactRetransmission(const ipmanipulator_tls_capture_slot_t *slot,
                                                           const ipmanipulator_tcp_packet_info_t  *info)
{
    if (slot == NULL || info == NULL || info->tcp_payload_len == 0)
    {
        return false;
    }

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        const ipmanipulator_captured_packet_t *captured      = &slot->captured_packets[i];
        ipmanipulator_tcp_packet_info_t        captured_info = {0};

        if (captured->buf == NULL ||
            ! ipmanipulatorParseTcpPacketInfo(
                (const uint8_t *) sbufGetRawPtr(captured->buf), sbufGetLength(captured->buf), &captured_info) ||
            captured_info.seq != info->seq || captured_info.tcp_payload_len != info->tcp_payload_len)
        {
            continue;
        }

        if (memoryCompare(captured_info.payload, info->payload, info->tcp_payload_len) == 0)
        {
            return true;
        }
    }

    return false;
}

static void ipmanipulatorDrainPrestartPacketsIntoCaptureSlot(ipmanipulator_tls_prestart_slot_t *prestart_slot,
                                                             ipmanipulator_tls_capture_slot_t  *capture_slot,
                                                             bool                              *complete)
{
    if (prestart_slot == NULL || capture_slot == NULL || complete == NULL)
    {
        return;
    }

    for (;;)
    {
        bool matched_entry = false;

        for (uint8_t i = 0; i < prestart_slot->captured_packets_count; ++i)
        {
            ipmanipulator_captured_packet_t *entry = &prestart_slot->captured_packets[i];
            ipmanipulator_tcp_packet_info_t  info  = {0};

            if (entry->buf == NULL ||
                ! ipmanipulatorParseTcpPacketInfo(
                    (const uint8_t *) sbufGetRawPtr(entry->buf), sbufGetLength(entry->buf), &info) ||
                info.seq != capture_slot->next_seq)
            {
                continue;
            }

            if (! ipmanipulatorAppendPacketToCaptureSlot(capture_slot, entry->line, entry->buf, &info, complete))
            {
                return;
            }

            matched_entry = true;

            for (uint8_t move_i = i + 1; move_i < prestart_slot->captured_packets_count; ++move_i)
            {
                prestart_slot->captured_packets[move_i - 1] = prestart_slot->captured_packets[move_i];
            }

            prestart_slot->captured_packets_count -= 1;
            memoryZero(&prestart_slot->captured_packets[prestart_slot->captured_packets_count],
                       sizeof(prestart_slot->captured_packets[0]));

            if (*complete)
            {
                ipmanipulatorResetPrestartSlot(prestart_slot);
                return;
            }

            break;
        }

        if (! matched_entry)
        {
            if (prestart_slot->captured_packets_count == 0)
            {
                ipmanipulatorResetPrestartSlot(prestart_slot);
            }
            return;
        }
    }
}

static uint8_t ipmanipulatorGetSegmentFlags(uint8_t original_flags, bool first_segment, bool final_segment)
{
    uint8_t flags = (uint8_t) (original_flags & (TCP_ACK | TCP_ECE));

    if (first_segment)
    {
        flags |= (uint8_t) (original_flags & (TCP_SYN | TCP_CWR));
    }

    if (final_segment)
    {
        flags |= (uint8_t) (original_flags & (TCP_FIN | TCP_PSH));
    }

    return flags;
}

static uint8_t ipmanipulatorGetAllTcpFlags(const struct tcp_hdr *tcp_header)
{
    return (uint8_t) (lwip_ntohs(tcp_header->_hdrlen_rsvd_flags) & 0x00FFU);
}

static void ipmanipulatorSetAllTcpFlags(struct tcp_hdr *tcp_header, uint8_t flags)
{
    uint16_t header_word = lwip_ntohs(tcp_header->_hdrlen_rsvd_flags);

    header_word                    = (uint16_t) ((header_word & 0xFF00U) | flags);
    tcp_header->_hdrlen_rsvd_flags = lwip_htons(header_word);
}

static bool ipmanipulatorPacketUsesMappedProtocol(const ipmanipulator_tstate_t *state, const sbuf_t *buf)
{
    if (sbufGetLength(buf) < sizeof(struct ip_hdr))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);
    if (IPH_V(ipheader) != 4)
    {
        return false;
    }

    uint8_t protocol = IPH_PROTO(ipheader);
    return protocol == state->trick_proto_swap_tcp_number || protocol == state->trick_proto_swap_udp_number;
}

static bool ipmanipulatorHasTcpBitActionsForDirection(const ipmanipulator_tstate_t *state, bool upstream)
{
    if (upstream)
    {
        return state->up_tcp_bit_cwr_action != kDvsNoAction || state->up_tcp_bit_ece_action != kDvsNoAction ||
               state->up_tcp_bit_urg_action != kDvsNoAction || state->up_tcp_bit_ack_action != kDvsNoAction ||
               state->up_tcp_bit_psh_action != kDvsNoAction || state->up_tcp_bit_rst_action != kDvsNoAction ||
               state->up_tcp_bit_syn_action != kDvsNoAction || state->up_tcp_bit_fin_action != kDvsNoAction;
    }

    return state->down_tcp_bit_cwr_action != kDvsNoAction || state->down_tcp_bit_ece_action != kDvsNoAction ||
           state->down_tcp_bit_urg_action != kDvsNoAction || state->down_tcp_bit_ack_action != kDvsNoAction ||
           state->down_tcp_bit_psh_action != kDvsNoAction || state->down_tcp_bit_rst_action != kDvsNoAction ||
           state->down_tcp_bit_syn_action != kDvsNoAction || state->down_tcp_bit_fin_action != kDvsNoAction;
}

static bool ipmanipulatorPrepareSingleEgressPacket(tunnel_t *t, line_t *l, sbuf_t **buf_ptr, bool upstream,
                                                   bool apply_portghost)
{
    ipmanipulator_tstate_t *state                = tunnelGetState(t);
    bool                    recalculate_checksum = lineGetRecalculateChecksum(l);
    bool                    ghost_applied        = false;
    sbuf_t                 *buf                  = *buf_ptr;

    if (apply_portghost)
    {
        ghost_applied = portghosttrickApply(t, l, &buf);
    }

    if (buf == NULL)
    {
        *buf_ptr = NULL;
        return false;
    }

    recalculate_checksum |= ghost_applied;
    lineSetRecalculateChecksum(l, recalculate_checksum);

    if (upstream && state->trick_proto_swap)
    {
        /*
         * Chained transport pair: a packet already carrying one of our mapped
         * values was wrapped by an earlier IpManipulator, and this node is the
         * unwrapping half. Restore the real protocol, checksum under it, and
         * forward unmapped. Do NOT re-map -- an operator who wants the packet
         * to stay wrapped past this node simply does not enable protoswap here.
         */
        if (ipmanipulatorPacketUsesMappedProtocol(state, buf))
        {
            protoswaptrickUpStreamPayload(t, l, buf);
            if (recalculate_checksum && calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)))
            {
                lineSetRecalculateChecksum(l, false);
            }
        }
        else
        {
            if (recalculate_checksum && calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)))
            {
                lineSetRecalculateChecksum(l, false);
            }
            protoswaptrickUpStreamPayload(t, l, buf);
        }
    }

    *buf_ptr = buf;
    return true;
}

static bool ipmanipulatorForwardSingleEgressPacket(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward,
                                                   bool upstream, bool apply_portghost)
{
    if (! ipmanipulatorPrepareSingleEgressPacket(t, l, &buf, upstream, apply_portghost))
    {
        return lineIsAlive(l);
    }

    forward(t, l, buf);
    return lineIsAlive(l);
}

static bool ipmanipulatorSendEgressMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward,
                                                  bool upstream, bool apply_portghost)
{
    ipmanipulator_tstate_t *state  = tunnelGetState(t);
    uint8_t                *packet = sbufGetMutablePtr(buf);

    if (sbufGetLength(buf) < sizeof(struct ip_hdr))
    {
        return ipmanipulatorForwardSingleEgressPacket(t, l, buf, forward, upstream, apply_portghost);
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4)
    {
        return ipmanipulatorForwardSingleEgressPacket(t, l, buf, forward, upstream, apply_portghost);
    }

    uint8_t ip_header_words = IPH_HL(ipheader);
    if (ip_header_words < 5 || ip_header_words > 15)
    {
        LOGW("IpManipulator: dropping packet with an invalid IPv4 header length before final egress");
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    uint16_t ip_header_len = (uint16_t) (ip_header_words * 4U);
    uint16_t ip_total_len  = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < ip_header_len || ip_total_len > sbufGetLength(buf))
    {
        LOGW("IpManipulator: dropping packet with an invalid IPv4 total length before final egress");
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    uint32_t portghost_tail_len = apply_portghost ? portghosttrickGetTailLength(state) : 0;
    uint8_t  transport_protocol = ipmanipulatorResolveTransportProtocol(state, IPH_PROTO(ipheader));
    uint16_t fragment_state     = lwip_ntohs(IPH_OFFSET(ipheader));

    /* These trailer transforms intentionally skip IPv4 fragments. Preserve
     * their fail-open path instead of treating unapplied trailer overhead as a
     * reason to segment or drop the fragment. */
    if ((fragment_state & (IP_MF | IP_OFFMASK)) != 0)
    {
        return ipmanipulatorForwardSingleEgressPacket(t, l, buf, forward, upstream, apply_portghost);
    }

    /* Unit fixtures and pre-start construction may not have installed the
     * runtime MTU yet. Zero means no final-MTU shaping is available. */
    if (GLOBAL_MTU_SIZE == 0)
    {
        return ipmanipulatorForwardSingleEgressPacket(t, l, buf, forward, upstream, apply_portghost);
    }

    uint32_t prospective_len = (uint32_t) ip_total_len + portghost_tail_len;
    if (prospective_len <= GLOBAL_MTU_SIZE)
    {
        /* Protocol swap historically accepts opaque packet-mode fixtures that
         * identify the IPv4 protocol as TCP without carrying a TCP header.
         * Transport parsing is needed only when final MTU shaping is actually
         * required; the individual trailer helpers still validate packets
         * before mutating an in-MTU packet. */
        return ipmanipulatorForwardSingleEgressPacket(t, l, buf, forward, upstream, apply_portghost);
    }

    if (transport_protocol != IPPROTO_TCP)
    {
        if (portghost_tail_len > 0 && (uint32_t) ip_total_len + portghost_tail_len > GLOBAL_MTU_SIZE)
        {
            if (ipmanipulatorShouldLogEgressWarning(state))
            {
                LOGW("IpManipulator: dropping non-TCP IPv4 packet because its %u-byte trailer would exceed "
                     "GLOBAL_MTU_SIZE %u; IPv4 fragmentation is not supported",
                     (unsigned int) portghost_tail_len,
                     (unsigned int) GLOBAL_MTU_SIZE);
            }
            reuseBuffer(buf);
            return lineIsAlive(l);
        }

        return ipmanipulatorForwardSingleEgressPacket(t, l, buf, forward, upstream, apply_portghost);
    }

    if (ip_total_len < ip_header_len + sizeof(struct tcp_hdr))
    {
        LOGW("IpManipulator: dropping truncated TCP packet before final egress");
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    struct tcp_hdr *tcp_header       = (struct tcp_hdr *) (packet + ip_header_len);
    uint8_t         tcp_header_words = TCPH_HDRLEN(tcp_header);
    if (tcp_header_words < 5 || tcp_header_words > 15)
    {
        LOGW("IpManipulator: dropping packet with an invalid TCP header length before final egress");
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    uint16_t tcp_header_len = (uint16_t) (tcp_header_words * 4U);
    uint32_t headers_len    = (uint32_t) ip_header_len + tcp_header_len;
    if (ip_total_len < headers_len)
    {
        LOGW("IpManipulator: dropping packet whose IPv4 length truncates its TCP header before final egress");
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    bool has_flag_metadata =
        state->trick_preserve_tcp_bitflags && ipmanipulatorHasTcpBitActionsForDirection(state, upstream);
    uint32_t flag_metadata_len = has_flag_metadata ? 1U : 0U;
    if ((uint32_t) ip_total_len < headers_len + flag_metadata_len)
    {
        LOGW("IpManipulator: dropping TCP packet without its configured preserved-flags metadata");
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    uint8_t live_flags        = ipmanipulatorGetAllTcpFlags(tcp_header);
    uint8_t original_flags    = has_flag_metadata ? packet[ip_total_len - 1U] : live_flags;
    uint8_t unsupported_flags = (uint8_t) ((live_flags | original_flags) & (TCP_RST | TCP_URG));
    if (unsupported_flags != 0)
    {
        if (ipmanipulatorShouldLogEgressWarning(state))
        {
            LOGW("IpManipulator: dropping oversized TCP packet because live or preserved-original %s segmentation "
                 "is unsupported",
                 (unsupported_flags & TCP_RST) != 0 ? "RST" : "URG");
        }
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    uint32_t total_payload_len = (uint32_t) ip_total_len - headers_len - flag_metadata_len;
    uint32_t segment_overhead  = portghost_tail_len + flag_metadata_len;
    if (total_payload_len == 0 || headers_len + segment_overhead >= GLOBAL_MTU_SIZE)
    {
        if (ipmanipulatorShouldLogEgressWarning(state))
        {
            LOGW("IpManipulator: dropping oversized TCP packet because IPv4/TCP headers and configured trailers "
                 "leave no segmentable payload within GLOBAL_MTU_SIZE %u",
                 (unsigned int) GLOBAL_MTU_SIZE);
        }
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    const uint8_t *source_payload      = packet + headers_len;
    uint32_t       max_segment_payload = (uint32_t) GLOBAL_MTU_SIZE - headers_len - segment_overhead;
    uint32_t       payload_offset      = 0;
    uint32_t       segment_index       = 0;
    uint32_t       base_seq            = lwip_ntohl(tcp_header->seqno);
    uint16_t       base_identification = lwip_ntohs(IPH_ID(ipheader));
    /* When preservation is enabled, the peer restores original_flags before
     * its TCP stack observes the segments. Otherwise original_flags is the
     * same value as live_flags. */
    bool syn_consumes_seq = (original_flags & TCP_SYN) != 0;
    bool line_alive       = true;

    LOGD("IpManipulator: segmenting TCP packet ip-len=%u payload=%u mtu=%u segment-payload=%u",
         ip_total_len,
         total_payload_len,
         GLOBAL_MTU_SIZE,
         max_segment_payload);

    lineLock(l);

    while (payload_offset < total_payload_len)
    {
        uint32_t this_payload_len = min(max_segment_payload, total_payload_len - payload_offset);
        uint32_t this_packet_len  = headers_len + this_payload_len;
        uint32_t required_len     = this_packet_len + flag_metadata_len + portghost_tail_len;
        sbuf_t  *segment_buf      = clonePacketWithLength(l, buf, required_len);

        if (segment_buf == NULL)
        {
            break;
        }

        sbufSetLength(segment_buf, this_packet_len);

        uint8_t *segment_packet = sbufGetMutablePtr(segment_buf);
        memoryCopyLarge(segment_packet, packet, headers_len);
        memoryCopyLarge(segment_packet + headers_len, source_payload + payload_offset, this_payload_len);

        struct ip_hdr  *segment_ipheader   = (struct ip_hdr *) segment_packet;
        struct tcp_hdr *segment_tcpheader  = (struct tcp_hdr *) (segment_packet + ip_header_len);
        bool            first_segment      = payload_offset == 0;
        bool            final_segment      = payload_offset + this_payload_len == total_payload_len;
        uint8_t         segment_live_flags = ipmanipulatorGetSegmentFlags(live_flags, first_segment, final_segment);
        uint8_t segment_original_flags     = ipmanipulatorGetSegmentFlags(original_flags, first_segment, final_segment);

        if (has_flag_metadata)
        {
            segment_packet[this_packet_len] = segment_original_flags;
            this_packet_len += 1U;
            sbufSetLength(segment_buf, this_packet_len);
        }

        IPH_LEN_SET(segment_ipheader, lwip_htons((uint16_t) this_packet_len));
        IPH_ID_SET(segment_ipheader, lwip_htons((uint16_t) (base_identification + (uint16_t) segment_index)));
        IPH_OFFSET_SET(segment_ipheader, lwip_htons((uint16_t) (fragment_state & ~(IP_MF | IP_OFFMASK))));
        segment_tcpheader->seqno =
            lwip_htonl(base_seq + payload_offset + (! first_segment && syn_consumes_seq ? 1U : 0U));
        ipmanipulatorSetAllTcpFlags(segment_tcpheader, segment_live_flags);

        lineSetRecalculateChecksum(l, true);
        line_alive = ipmanipulatorForwardSingleEgressPacket(t, l, segment_buf, forward, upstream, apply_portghost);
        if (! line_alive)
        {
            break;
        }

        payload_offset += this_payload_len;
        segment_index += 1;
    }

    lineUnlock(l);
    reuseBuffer(buf);
    return line_alive;
}

void ipmanipulatorEmitUpstream(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    discard ipmanipulatorSendEgressMaybeSegmented(t, l, buf, forward, true, true);
}

void ipmanipulatorEmitUpstreamPreservingTuple(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    discard ipmanipulatorSendEgressMaybeSegmented(t, l, buf, forward, true, false);
}

bool ipmanipulatorSendWithForwardMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    lineSetRecalculateChecksum(l, true);
    return ipmanipulatorSendEgressMaybeSegmented(t, l, buf, forward, true, true);
}

bool ipmanipulatorSendUpstreamMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    return ipmanipulatorSendWithForwardMaybeSegmented(t, l, buf, tunnelNextUpStreamPayload);
}

typedef struct ipmanipulator_delay_timer_message_s
{
    ipmanipulator_flow_key_t           key;
    ipmanipulator_delay_barrier_kind_e kind;
    uint64_t                           generation;
} ipmanipulator_delay_timer_message_t;

static uint64_t ipmanipulatorAllocateDelayGeneration(ipmanipulator_tstate_t *state)
{
    uint64_t generation = 0;

    while (generation == 0)
    {
        generation = atomicIncU64Relaxed(&state->delay_barrier_next_generation) + 1U;
    }

    return generation;
}

void ipmanipulatorDelayBarrierDestroy(ipmanipulator_delay_barrier_t *barrier)
{
    if (barrier == NULL)
    {
        return;
    }

    for (uint8_t i = 0; i < barrier->count; ++i)
    {
        ipmanipulator_captured_packet_t *packet = &barrier->packets[i];

        if (packet->buf != NULL)
        {
            sbufDestroy(packet->buf);
        }
        if (packet->line != NULL)
        {
            lineUnlock(packet->line);
        }
    }

    for (uint32_t i = barrier->next_ordered_output; i < barrier->ordered_outputs_count; ++i)
    {
        ipmanipulator_ordered_output_t *output = &barrier->ordered_outputs[i];

        if (output->buf != NULL)
        {
            sbufDestroy(output->buf);
        }
        if (output->line != NULL)
        {
            lineUnlock(output->line);
        }
    }
    memoryFree(barrier->ordered_outputs);

    memoryZero(barrier, sizeof(*barrier));
}

void ipmanipulatorDelayBarrierInitialize(ipmanipulator_tstate_t *state, ipmanipulator_delay_barrier_t *barrier,
                                         uint64_t deadline_ms)
{
    if (state == NULL || barrier == NULL)
    {
        return;
    }

    ipmanipulatorDelayBarrierDestroy(barrier);
    if (deadline_ms == 0)
    {
        return;
    }

    barrier->generation  = ipmanipulatorAllocateDelayGeneration(state);
    barrier->deadline_ms = deadline_ms;
}

bool ipmanipulatorDelayBarrierTryEnqueue(ipmanipulator_delay_barrier_t *barrier, line_t *l, sbuf_t *buf,
                                         bool remove_after_release, bool *needs_schedule)
{
    if (needs_schedule != NULL)
    {
        *needs_schedule = false;
    }

    if (barrier == NULL || l == NULL || buf == NULL || barrier->deadline_ms == 0)
    {
        return false;
    }

    uint32_t packet_len = sbufGetLength(buf);
    if (barrier->count >= kIpManipulatorDelayBarrierMaxPackets ||
        packet_len > kIpManipulatorDelayBarrierMaxBytes - barrier->retained_bytes)
    {
        return false;
    }

    lineLock(l);
    barrier->packets[barrier->count] = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
    barrier->count += 1U;
    barrier->retained_bytes += packet_len;
    barrier->remove_after_release |= remove_after_release;

    if (! barrier->timer_armed)
    {
        barrier->timer_armed = true;
        if (needs_schedule != NULL)
        {
            *needs_schedule = true;
        }
    }

    return true;
}

bool ipmanipulatorDelayBarrierInstallOrdered(ipmanipulator_delay_barrier_t  *barrier,
                                             ipmanipulator_ordered_output_t *outputs, uint32_t count,
                                             bool *needs_schedule)
{
    if (needs_schedule != NULL)
    {
        *needs_schedule = false;
    }

    if (barrier == NULL || barrier->deadline_ms == 0 || outputs == NULL || count == 0 ||
        barrier->ordered_outputs != NULL)
    {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        if (outputs[i].line == NULL || outputs[i].buf == NULL || outputs[i].send == NULL ||
            (i > 0 && outputs[i].due_ms < outputs[i - 1U].due_ms))
        {
            return false;
        }
    }

    ipmanipulator_ordered_output_t *owned_outputs = memoryAllocateZero(sizeof(*owned_outputs) * count);
    if (owned_outputs == NULL)
    {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        lineLock(outputs[i].line);
        owned_outputs[i] = outputs[i];
        outputs[i].line  = NULL;
        outputs[i].buf   = NULL;
    }

    barrier->ordered_outputs       = owned_outputs;
    barrier->ordered_outputs_count = count;
    barrier->next_ordered_output   = 0;

    if (! barrier->timer_armed)
    {
        barrier->timer_armed = true;
        if (needs_schedule != NULL)
        {
            *needs_schedule = true;
        }
    }

    return true;
}

bool ipmanipulatorDelayBarrierHasPendingOrdered(const ipmanipulator_delay_barrier_t *barrier)
{
    return barrier != NULL && barrier->ordered_outputs != NULL &&
           barrier->next_ordered_output < barrier->ordered_outputs_count;
}

void ipmanipulatorDelayBarrierTake(ipmanipulator_delay_barrier_t *barrier, ipmanipulator_delay_batch_t *batch)
{
    if (barrier == NULL || batch == NULL)
    {
        return;
    }

    memoryZero(batch, sizeof(*batch));
    batch->count                 = barrier->count;
    batch->ordered_outputs       = barrier->ordered_outputs;
    batch->ordered_outputs_count = barrier->ordered_outputs_count;
    batch->next_ordered_output   = barrier->next_ordered_output;
    for (uint8_t i = 0; i < barrier->count; ++i)
    {
        batch->packets[i] = barrier->packets[i];
    }

    memoryZero(barrier, sizeof(*barrier));
}

bool ipmanipulatorDelayBatchSendUpstream(tunnel_t *t, ipmanipulator_delay_batch_t *batch)
{
    if (batch == NULL)
    {
        return true;
    }

    bool all_alive = true;

    for (uint32_t i = batch->next_ordered_output; i < batch->ordered_outputs_count; ++i)
    {
        ipmanipulator_ordered_output_t *output = &batch->ordered_outputs[i];

        if (output->line == NULL)
        {
            if (output->buf != NULL)
            {
                sbufDestroy(output->buf);
            }
        }
        else if (output->buf != NULL)
        {
            if (lineIsAlive(output->line))
            {
                output->send(t, output->line, output->buf);
                all_alive &= lineIsAlive(output->line);
            }
            else
            {
                lineReuseBuffer(output->line, output->buf);
                all_alive = false;
            }

            lineUnlock(output->line);
        }

        output->line = NULL;
        output->buf  = NULL;
    }

    memoryFree(batch->ordered_outputs);
    batch->ordered_outputs       = NULL;
    batch->ordered_outputs_count = 0;
    batch->next_ordered_output   = 0;

    for (uint8_t i = 0; i < batch->count; ++i)
    {
        ipmanipulator_captured_packet_t *packet = &batch->packets[i];

        if (packet->line == NULL)
        {
            if (packet->buf != NULL)
            {
                sbufDestroy(packet->buf);
            }
        }
        else if (packet->buf != NULL)
        {
            if (lineIsAlive(packet->line))
            {
                all_alive &= ipmanipulatorSendUpstreamMaybeSegmented(t, packet->line, packet->buf);
            }
            else
            {
                lineReuseBuffer(packet->line, packet->buf);
                all_alive = false;
            }

            lineUnlock(packet->line);
        }

        packet->line = NULL;
        packet->buf  = NULL;
    }

    batch->count = 0;
    return all_alive;
}

static ipmanipulator_flow_table_t *ipmanipulatorDelayBarrierTable(ipmanipulator_tstate_t            *state,
                                                                  ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        return &state->first_sni_table;
    case kIpManipulatorDelayBarrierSmuggleSni:
        return &state->smuggle_table;
    case kIpManipulatorDelayBarrierOverlapSni:
        return &state->overlap_table;
    default:
        return NULL;
    }
}

static ipmanipulator_delay_barrier_t *ipmanipulatorDelayBarrierFromRecord(void                              *record,
                                                                          ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        return &((ipmanipulator_firstsni_flow_t *) record)->delay_barrier;
    case kIpManipulatorDelayBarrierSmuggleSni:
        return &((ipmanipulator_smuggle_flow_t *) record)->delay_barrier;
    case kIpManipulatorDelayBarrierOverlapSni:
        return &((ipmanipulator_overlap_flow_t *) record)->delay_barrier;
    default:
        return NULL;
    }
}

static void ipmanipulatorDelayBarrierClearWindow(void *record, ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        ((ipmanipulator_firstsni_flow_t *) record)->delay_window_until_ms = 0;
        return;
    case kIpManipulatorDelayBarrierSmuggleSni:
        ((ipmanipulator_smuggle_flow_t *) record)->delay_window_until_ms = 0;
        return;
    case kIpManipulatorDelayBarrierOverlapSni:
        ((ipmanipulator_overlap_flow_t *) record)->delay_window_until_ms = 0;
        return;
    default:
        return;
    }
}

static void ipmanipulatorDelayBarrierCleanupTimer(void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg3;

    memoryFree(arg2);
}

#ifdef IPMANIPULATOR_DELAY_BARRIER_TEST_HOOKS
static uint64_t ipmanipulator_delay_barrier_test_now_ms;

void ipmanipulatorDelayBarrierTestSetNow(uint64_t now_ms)
{
    ipmanipulator_delay_barrier_test_now_ms = now_ms;
}

static uint64_t ipmanipulatorDelayBarrierNow(void)
{
    return ipmanipulator_delay_barrier_test_now_ms;
}
#else
static uint64_t ipmanipulatorDelayBarrierNow(void)
{
    return getTickMS();
}
#endif

static void ipmanipulatorDelayBarrierRunTimer(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg3;

    // Reschedules below must stay on the worker this message was delivered to.
    assert(currentThreadIsEventWorkerWID(worker->wid));

    tunnel_t                            *t     = arg1;
    ipmanipulator_delay_timer_message_t *msg   = arg2;
    ipmanipulator_tstate_t              *state = tunnelGetState(t);
    ipmanipulator_flow_table_t          *table = ipmanipulatorDelayBarrierTable(state, msg->kind);

    if (table == NULL)
    {
        memoryFree(msg);
        return;
    }

    for (;;)
    {
        ipmanipulator_delay_batch_t    batch                = {0};
        ipmanipulator_ordered_output_t due_output           = {0};
        bool                           have_due_output      = false;
        bool                           remove_after_release = false;
        uint64_t                       now_ms               = ipmanipulatorDelayBarrierNow();
        ipmanipulator_flow_shard_t    *shard                = ipmanipulatorFlowTableLockShard(table, &msg->key);

        if (shard == NULL)
        {
            memoryFree(msg);
            return;
        }

        ipmanipulator_flow_entry_t    *entry = ipmanipulatorFlowShardFind(table, shard, &msg->key);
        ipmanipulator_delay_barrier_t *barrier =
            entry != NULL ? ipmanipulatorDelayBarrierFromRecord(ipmanipulatorFlowEntryRecord(entry), msg->kind) : NULL;

        if (barrier == NULL || barrier->generation != msg->generation || ! barrier->timer_armed)
        {
            ipmanipulatorFlowShardUnlock(shard);
            memoryFree(msg);
            return;
        }

        if (ipmanipulatorDelayBarrierHasPendingOrdered(barrier))
        {
            ipmanipulator_ordered_output_t *next = &barrier->ordered_outputs[barrier->next_ordered_output];

            if (now_ms < next->due_ms)
            {
                uint64_t remaining = next->due_ms - now_ms;
                uint32_t delay_ms  = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining;
                wid_t    wid       = worker->wid;

                ipmanipulatorFlowShardUnlock(shard);
                ipmanipulatorDelayBarrierSchedule(t, &msg->key, msg->kind, msg->generation, wid, delay_ms);
                memoryFree(msg);
                return;
            }

            due_output = *next;
            memoryZero(next, sizeof(*next));
            barrier->next_ordered_output += 1U;
            have_due_output = true;
        }
        else if (now_ms < barrier->deadline_ms)
        {
            uint64_t remaining = barrier->deadline_ms - now_ms;
            uint32_t delay_ms  = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining;
            wid_t    wid       = worker->wid;

            ipmanipulatorFlowShardUnlock(shard);
            ipmanipulatorDelayBarrierSchedule(t, &msg->key, msg->kind, msg->generation, wid, delay_ms);
            memoryFree(msg);
            return;
        }
        else
        {
            remove_after_release = barrier->remove_after_release;
            ipmanipulatorDelayBarrierTake(barrier, &batch);
            ipmanipulatorDelayBarrierClearWindow(ipmanipulatorFlowEntryRecord(entry), msg->kind);

            if (remove_after_release)
            {
                ipmanipulatorFlowShardRemove(table, shard, entry);
            }
        }

        ipmanipulatorFlowShardUnlock(shard);

        if (have_due_output)
        {
            if (due_output.line == NULL)
            {
                if (due_output.buf != NULL)
                {
                    sbufDestroy(due_output.buf);
                }
            }
            else if (due_output.buf != NULL)
            {
                if (lineIsAlive(due_output.line))
                {
                    due_output.send(t, due_output.line, due_output.buf);
                }
                else
                {
                    lineReuseBuffer(due_output.line, due_output.buf);
                }
                lineUnlock(due_output.line);
            }

            continue;
        }

        memoryFree(msg);
        discard ipmanipulatorDelayBatchSendUpstream(t, &batch);
        return;
    }
}

#ifdef IPMANIPULATOR_DELAY_BARRIER_TEST_HOOKS
void ipmanipulatorDelayBarrierTestFire(tunnel_t *t, const ipmanipulator_flow_key_t *key,
                                       ipmanipulator_delay_barrier_kind_e kind, uint64_t generation)
{
    ipmanipulator_delay_timer_message_t *msg = memoryAllocate(sizeof(*msg));

    *msg = (ipmanipulator_delay_timer_message_t) {.key = *key, .kind = kind, .generation = generation};

    /*
     * Fire it exactly as the worker-message path would: the callback takes its
     * identity from the worker it was delivered to, so the hook must hand over
     * the current event worker rather than a null placeholder.
     */
    ipmanipulatorDelayBarrierRunTimer(getCurrentEventWorker(), t, msg, NULL);
}
#endif

void ipmanipulatorDelayBarrierSchedule(tunnel_t *t, const ipmanipulator_flow_key_t *key,
                                       ipmanipulator_delay_barrier_kind_e kind, uint64_t generation, wid_t wid,
                                       uint32_t delay_ms)
{
    ipmanipulator_delay_timer_message_t *msg = memoryAllocate(sizeof(*msg));

    *msg = (ipmanipulator_delay_timer_message_t) {.key = *key, .kind = kind, .generation = generation};
    sendWorkerMessageTimedWithCleanup(wid,
                                      (WorkerMessageCallback) ipmanipulatorDelayBarrierRunTimer,
                                      ipmanipulatorDelayBarrierCleanupTimer,
                                      delay_ms,
                                      t,
                                      msg,
                                      NULL);
}

ipmanipulator_tls_capture_status_e ipmanipulatorCaptureTlsClientHello(tunnel_t *t, line_t *l, sbuf_t *buf,
                                                                      ipmanipulator_tls_capture_kind_e  kind,
                                                                      ipmanipulator_tls_capture_slot_t *out_slot)
{
    return ipmanipulatorCaptureTlsClientHelloForOwner(t, l, buf, kind, 0, out_slot);
}

ipmanipulator_tls_capture_status_e ipmanipulatorCaptureTlsClientHelloForOwner(
    tunnel_t *t, line_t *l, sbuf_t *buf, ipmanipulator_tls_capture_kind_e kind, uint64_t owner_generation,
    ipmanipulator_tls_capture_slot_t *out_slot)
{
    ipmanipulator_tstate_t           *state                 = tunnelGetState(t);
    ipmanipulator_tcp_packet_info_t   info                  = {0};
    ipmanipulator_tls_capture_slot_t  release_slot          = {0};
    ipmanipulator_tls_prestart_slot_t release_prestart_slot = {0};
    bool                              have_release          = false;
    bool                              have_prestart_release = false;
    bool                              allow_prestart        = ipmanipulatorTlsCaptureKindAllowsPrestart(kind);

    ipmanipulatorResetCapturedSlot(out_slot);

    if (! ipmanipulatorParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return kIpManipulatorTlsCaptureStatusMiss;
    }

    mutexLock(&state->tls_capture_mutex);

    uint64_t now_ms         = getTickMS();
    int      matched_index  = -1;
    int      prestart_index = -1;

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        ipmanipulator_tls_capture_slot_t *slot = &state->tls_capture_slots[i];

        if (! slot->active)
        {
            continue;
        }

        if (now_ms - slot->last_update_ms >= kIpManipulatorTlsCaptureTimeoutMs)
        {
            if (! have_release)
            {
                ipmanipulatorTakeCapturedSlot(&release_slot, slot);
                have_release = true;
            }
            continue;
        }

        if (ipmanipulatorTlsCaptureSlotMatches(slot, &info, kind, owner_generation))
        {
            matched_index = (int) i;
            break;
        }
    }

    if (allow_prestart)
    {
        for (uint32_t i = 0; i < state->tls_prestart_slots_count; ++i)
        {
            ipmanipulator_tls_prestart_slot_t *slot = &state->tls_prestart_slots[i];

            if (! slot->active)
            {
                continue;
            }

            if (now_ms - slot->last_update_ms >= kIpManipulatorTlsPrestartTimeoutMs)
            {
                if (! have_prestart_release)
                {
                    ipmanipulatorTakePrestartSlot(&release_prestart_slot, slot);
                    have_prestart_release = true;
                }
                continue;
            }

            if (ipmanipulatorTlsPrestartSlotMatches(slot, &info, kind))
            {
                prestart_index = (int) i;
                break;
            }
        }
    }

    if (matched_index >= 0)
    {
        ipmanipulator_tls_capture_slot_t *slot     = &state->tls_capture_slots[matched_index];
        bool                              complete = false;

        if (kind == kIpManipulatorTlsCaptureKindEchSni && ipmanipulatorCaptureSlotHasExactRetransmission(slot, &info))
        {
            slot->last_update_ms = now_ms;
            ipmanipulatorScheduleCaptureTimeout(t, (uint32_t) matched_index, slot->generation);
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            /* The already-held segment is the original; recycle this duplicate. */
            ipmanipulatorScheduleCapturedPacketReuse(l, buf);
            return kIpManipulatorTlsCaptureStatusPending;
        }

        bool appended = ipmanipulatorAppendPacketToCaptureSlot(slot, l, buf, &info, &complete);

        if (appended && prestart_index >= 0 && ! complete)
        {
            ipmanipulatorDrainPrestartPacketsIntoCaptureSlot(
                &state->tls_prestart_slots[prestart_index], slot, &complete);
        }

        if (appended && complete)
        {
            LOGD("IpManipulator: %s completed fragmented TLS ClientHello capture packets=%u assembled-ip-len=%u",
                 ipmanipulatorTlsCaptureKindName(kind),
                 (unsigned int) slot->captured_packets_count,
                 sbufGetLength(slot->assembled_packet));

            ipmanipulatorTakeCapturedSlot(out_slot, slot);
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusReady;
        }

        if (appended)
        {
            ipmanipulatorScheduleCaptureTimeout(t, (uint32_t) matched_index, slot->generation);
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusPending;
        }

        ipmanipulatorTakeCapturedSlot(out_slot, slot);
        mutexUnlock(&state->tls_capture_mutex);

        if (have_release)
        {
            ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
        }
        if (have_prestart_release)
        {
            ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
        }

        ipmanipulatorReleaseCapturedPacketsNormal(t, out_slot);
        ipmanipulatorResetCapturedSlot(out_slot);
        ipmanipulatorScheduleCapturedPacketNormal(t, l, buf);
        return kIpManipulatorTlsCaptureStatusBypassed;
    }

    ipmanipulator_tls_clienthello_start_t        start = {0};
    ipmanipulator_tls_clienthello_start_status_t start_status =
        ipmanipulatorInspectTlsClientHelloStart((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &start);

    if (start_status == kIpManipulatorTlsClientHelloStartComplete)
    {
        sbuf_t *assembled = ipmanipulatorCreateStandalonePacketBuffer(buf, start.tcp.ip_total_len);
        if (assembled == NULL)
        {
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusMiss;
        }

        memoryCopyLarge(sbufGetMutablePtr(assembled), start.tcp.packet, start.tcp.ip_total_len);

        out_slot->assembled_packet        = assembled;
        out_slot->last_update_ms          = now_ms;
        out_slot->next_seq                = start.tcp.seq + start.tcp.tcp_payload_len;
        out_slot->tls_record_total_len    = start.tls_record_total_len;
        out_slot->tls_record_captured_len = start.tls_record_total_len;
        out_slot->captured_payload_len    = start.tcp.tcp_payload_len;
        out_slot->src_addr                = start.tcp.src_addr;
        out_slot->dst_addr                = start.tcp.dst_addr;
        out_slot->src_port                = start.tcp.src_port;
        out_slot->dst_port                = start.tcp.dst_port;
        out_slot->ip_header_len           = start.tcp.ip_header_len;
        out_slot->tcp_header_len          = start.tcp.tcp_header_len;
        out_slot->headers_len             = start.tcp.headers_len;
        out_slot->captured_packets_count  = 1;
        out_slot->kind                    = kind;
        out_slot->owner_generation        = owner_generation;
        out_slot->active                  = true;
        out_slot->captured_packets[0]     = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};

        mutexUnlock(&state->tls_capture_mutex);

        if (have_release)
        {
            ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
        }
        if (have_prestart_release)
        {
            ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
        }

        return kIpManipulatorTlsCaptureStatusReady;
    }

    bool capture_partial_ech =
        start_status == kIpManipulatorTlsClientHelloStartPartial && kind == kIpManipulatorTlsCaptureKindEchSni;

    if (start_status != kIpManipulatorTlsClientHelloStartFragmented && ! capture_partial_ech)
    {
        if (! allow_prestart)
        {
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusMiss;
        }

        if (start_status == kIpManipulatorTlsClientHelloStartUnsupported)
        {
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusMiss;
        }

        if (info.tcp_payload_len == 0)
        {
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusMiss;
        }

        if (prestart_index >= 0)
        {
            ipmanipulator_tls_prestart_slot_t *slot = &state->tls_prestart_slots[prestart_index];

            if (! ipmanipulatorAppendPacketToPrestartSlot(slot, l, buf, &info))
            {
                mutexUnlock(&state->tls_capture_mutex);

                if (have_release)
                {
                    ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
                }
                if (have_prestart_release)
                {
                    ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
                }

                return kIpManipulatorTlsCaptureStatusMiss;
            }

            ipmanipulatorSchedulePrestartTimeout(t, (uint32_t) prestart_index, slot->generation);
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusPending;
        }

        if (info.tcp_payload_len < kIpManipulatorTlsPrestartMinPayloadLen)
        {
            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusMiss;
        }

        int candidate_prestart_index = -1;
        int oldest_prestart_index    = -1;

        for (uint32_t i = 0; i < state->tls_prestart_slots_count; ++i)
        {
            ipmanipulator_tls_prestart_slot_t *slot = &state->tls_prestart_slots[i];

            if (! slot->active)
            {
                candidate_prestart_index = (int) i;
                break;
            }

            if (oldest_prestart_index < 0 ||
                slot->last_update_ms < state->tls_prestart_slots[oldest_prestart_index].last_update_ms)
            {
                oldest_prestart_index = (int) i;
            }
        }

        if (candidate_prestart_index < 0)
        {
            candidate_prestart_index = oldest_prestart_index;
            if (candidate_prestart_index >= 0 && ! have_prestart_release)
            {
                ipmanipulatorTakePrestartSlot(&release_prestart_slot,
                                              &state->tls_prestart_slots[candidate_prestart_index]);
                have_prestart_release = true;
            }
        }

        if (candidate_prestart_index >= 0)
        {
            ipmanipulator_tls_prestart_slot_t *slot = &state->tls_prestart_slots[candidate_prestart_index];

            *slot = (ipmanipulator_tls_prestart_slot_t) {
                .last_update_ms         = now_ms,
                .src_addr               = info.src_addr,
                .dst_addr               = info.dst_addr,
                .src_port               = info.src_port,
                .dst_port               = info.dst_port,
                .generation             = 1,
                .captured_packets_count = 0,
                .kind                   = kind,
                .active                 = true,
            };

            if (! ipmanipulatorAppendPacketToPrestartSlot(slot, l, buf, &info))
            {
                ipmanipulatorResetPrestartSlot(slot);
                mutexUnlock(&state->tls_capture_mutex);

                if (have_release)
                {
                    ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
                }
                if (have_prestart_release)
                {
                    ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
                }

                return kIpManipulatorTlsCaptureStatusMiss;
            }

            ipmanipulatorSchedulePrestartTimeout(t, (uint32_t) candidate_prestart_index, slot->generation);

            mutexUnlock(&state->tls_capture_mutex);

            if (have_release)
            {
                ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
            }
            if (have_prestart_release)
            {
                ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
            }

            return kIpManipulatorTlsCaptureStatusPending;
        }

        mutexUnlock(&state->tls_capture_mutex);

        if (have_release)
        {
            ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
        }
        if (have_prestart_release)
        {
            ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
        }

        return kIpManipulatorTlsCaptureStatusMiss;
    }

    int candidate_index = -1;
    int oldest_index    = -1;

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        ipmanipulator_tls_capture_slot_t *slot = &state->tls_capture_slots[i];

        if (! slot->active)
        {
            candidate_index = (int) i;
            break;
        }

        if (oldest_index < 0 || slot->last_update_ms < state->tls_capture_slots[oldest_index].last_update_ms)
        {
            oldest_index = (int) i;
        }
    }

    if (candidate_index < 0)
    {
        candidate_index = oldest_index;
        if (candidate_index >= 0)
        {
            ipmanipulatorTakeCapturedSlot(&release_slot, &state->tls_capture_slots[candidate_index]);
            have_release = true;
        }
    }

    if (candidate_index < 0)
    {
        mutexUnlock(&state->tls_capture_mutex);

        if (have_release)
        {
            ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
        }
        if (have_prestart_release)
        {
            ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
        }

        return kIpManipulatorTlsCaptureStatusMiss;
    }

    ipmanipulator_tls_capture_slot_t *slot = &state->tls_capture_slots[candidate_index];
    uint32_t                          assembled_capacity =
        start.tls_record_total_len != 0 ? start.tls_record_total_len : max((uint32_t) start.tcp.tcp_payload_len, 9U);
    *slot = (ipmanipulator_tls_capture_slot_t) {
        .assembled_packet = ipmanipulatorCreateStandalonePacketBuffer(buf, start.tcp.headers_len + assembled_capacity),
        .last_update_ms   = now_ms,
        .next_seq         = start.tcp.seq,
        .tls_record_total_len    = start.tls_record_total_len,
        .tls_record_captured_len = 0,
        .captured_payload_len    = 0,
        .src_addr                = start.tcp.src_addr,
        .dst_addr                = start.tcp.dst_addr,
        .src_port                = start.tcp.src_port,
        .dst_port                = start.tcp.dst_port,
        .ip_header_len           = start.tcp.ip_header_len,
        .tcp_header_len          = start.tcp.tcp_header_len,
        .headers_len             = start.tcp.headers_len,
        .captured_packets_count  = 0,
        .kind                    = kind,
        .owner_generation        = owner_generation,
        .active                  = true,
    };

    LOGD("IpManipulator: %s started fragmented TLS ClientHello capture payload=%u record=%u seq=%u %u:%u -> %u:%u",
         ipmanipulatorTlsCaptureKindName(kind),
         (unsigned int) start.tcp.tcp_payload_len,
         start.tls_record_total_len,
         start.tcp.seq,
         start.tcp.src_addr,
         (unsigned int) start.tcp.src_port,
         start.tcp.dst_addr,
         (unsigned int) start.tcp.dst_port);

    memoryCopyLarge(sbufGetMutablePtr(slot->assembled_packet), start.tcp.packet, slot->headers_len);

    bool    complete = false;
    bool    appended = ipmanipulatorAppendPacketToCaptureSlot(slot, l, buf, &start.tcp, &complete);
    discard complete;
    if (! appended)
    {
        if (slot->assembled_packet != NULL)
        {
            sbufDestroy(slot->assembled_packet);
            slot->assembled_packet = NULL;
        }
        ipmanipulatorResetCapturedSlot(slot);
        mutexUnlock(&state->tls_capture_mutex);

        if (have_release)
        {
            ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
        }
        if (have_prestart_release)
        {
            ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
        }

        return kIpManipulatorTlsCaptureStatusMiss;
    }

    if (prestart_index >= 0)
    {
        ipmanipulator_tls_prestart_slot_t *prestart_slot = &state->tls_prestart_slots[prestart_index];
        if (! complete)
        {
            ipmanipulatorDrainPrestartPacketsIntoCaptureSlot(prestart_slot, slot, &complete);
        }

        if (prestart_slot->active)
        {
            ipmanipulatorSchedulePrestartTimeout(t, (uint32_t) prestart_index, prestart_slot->generation);
        }
    }

    if (complete)
    {
        LOGD("IpManipulator: %s completed fragmented TLS ClientHello capture packets=%u assembled-ip-len=%u",
             ipmanipulatorTlsCaptureKindName(kind),
             (unsigned int) slot->captured_packets_count,
             sbufGetLength(slot->assembled_packet));

        ipmanipulatorTakeCapturedSlot(out_slot, slot);
        mutexUnlock(&state->tls_capture_mutex);

        if (have_release)
        {
            ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
        }
        if (have_prestart_release)
        {
            ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
        }

        return kIpManipulatorTlsCaptureStatusReady;
    }

    ipmanipulatorScheduleCaptureTimeout(t, (uint32_t) candidate_index, slot->generation);
    mutexUnlock(&state->tls_capture_mutex);

    if (have_release)
    {
        ipmanipulatorReleaseCapturedPacketsNormal(t, &release_slot);
    }
    if (have_prestart_release)
    {
        ipmanipulatorReleasePrestartPacketsNormal(t, &release_prestart_slot);
    }

    return kIpManipulatorTlsCaptureStatusPending;
}

void ipmanipulatorDestroyTlsCaptureState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->tls_capture_slots == NULL)
    {
        return;
    }

    mutexLock(&state->tls_capture_mutex);

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        ipmanipulatorDestroyCapturedTlsPackets(&state->tls_capture_slots[i]);
    }

    for (uint32_t i = 0; i < state->tls_prestart_slots_count; ++i)
    {
        ipmanipulatorDestroyPrestartPackets(&state->tls_prestart_slots[i]);
    }

    mutexUnlock(&state->tls_capture_mutex);
    mutexDestroy(&state->tls_capture_mutex);

    memoryFree(state->tls_capture_slots);
    memoryFree(state->tls_prestart_slots);
    state->tls_capture_slots        = NULL;
    state->tls_capture_slots_count  = 0;
    state->tls_prestart_slots       = NULL;
    state->tls_prestart_slots_count = 0;
}

sbuf_t *clonePacketWithLength(line_t *l, sbuf_t *buf, uint32_t new_len)
{
    sbuf_t *clone = bufferpoolGetBestFit(lineGetBufferPool(l), new_len, sbufGetLeftPadding(buf));

    sbufSetLength(clone, new_len);
    return clone;
}

bool parseTlsRecordSni(const uint8_t *tls, uint32_t tls_len, sni_match_t *match)
{
    if (match == NULL)
    {
        return false;
    }

    tls_client_hello_view_t hello = {0};
    if (tlsclienthelloParseRecord(tls, tls_len, &hello) != kTlsClientHelloFound ||
        hello.handshake_total_length != hello.record_body_length)
    {
        return false;
    }

    *match = (sni_match_t) {
        .tls_record_len                    = (uint16_t) hello.record_body_length,
        .client_hello_len                  = hello.handshake_body_length,
        .has_tls13_psk_binder              = hello.has_psk,
        .extensions_len                    = hello.extensions_length,
        .server_name_list_len              = hello.server_name_list_length,
        .server_name_ext_len               = hello.sni_extension_length,
        .sni_name_len                      = hello.sni_name_length,
        .sni_name_offset                   = hello.sni_name_offset,
        .sni_name_len_field_offset         = hello.sni_name_length_field_offset,
        .extensions_len_field_offset       = hello.extensions_length_field_offset,
        .server_name_list_len_field_offset = hello.server_name_list_length_field_offset,
        .server_name_ext_len_field_offset  = hello.sni_extension_length_field_offset,
        .tls_record_len_field_offset       = hello.record_length_field_offset,
        .client_hello_len_field_offset     = hello.handshake_length_field_offset,
    };
    return true;
}

bool parseClientHelloSni(const uint8_t *packet, uint32_t packet_length, sni_match_t *match)
{
    ipmanipulator_tcp_packet_info_t info = {0};
    if (! ipmanipulatorParseTcpPacketInfo(packet, packet_length, &info))
    {
        return false;
    }

    if (! parseTlsRecordSni(packet + info.headers_len, info.tcp_payload_len, match))
    {
        return false;
    }

    match->ip_total_len = info.ip_total_len;
    match->sni_name_offset += info.headers_len;
    match->sni_name_len_field_offset += info.headers_len;
    match->extensions_len_field_offset += info.headers_len;
    match->server_name_list_len_field_offset += info.headers_len;
    match->server_name_ext_len_field_offset += info.headers_len;
    match->tls_record_len_field_offset += info.headers_len;
    match->client_hello_len_field_offset += info.headers_len;
    return true;
}

static void ipmanipulatorSendWithDuplicates(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    ipmanipulator_tstate_t *state                = tunnelGetState(t);
    bool                    recalculate_checksum = lineGetRecalculateChecksum(l);

    if (! state->trick_packet_duplicate || state->trick_packet_duplicate_count <= 0)
    {
        lineSetRecalculateChecksum(l, recalculate_checksum);
        forward(t, l, buf);
        return;
    }

    buffer_pool_t *pool = lineGetBufferPool(l);

    lineLock(l);

    for (int i = 0; i < state->trick_packet_duplicate_count; ++i)
    {
        sbuf_t *dup = sbufDuplicateByPool(pool, buf);

        lineSetRecalculateChecksum(l, recalculate_checksum);
        forward(t, l, dup);

        if (! lineIsAlive(l))
        {
            reuseBuffer(buf);
            lineUnlock(l);
            return;
        }
    }

    lineSetRecalculateChecksum(l, recalculate_checksum);
    forward(t, l, buf);
    lineUnlock(l);
}

static void ipmanipulatorSendUpstreamDuplicates(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulatorSendWithDuplicates(t, l, buf, tunnelNextUpStreamPayload);
}

static void ipmanipulatorSendDownstreamDuplicates(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulatorSendWithDuplicates(t, l, buf, tunnelPrevDownStreamPayload);
}

void ipmanipulatorSendUpstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulatorEmitUpstream(t, l, buf, ipmanipulatorSendUpstreamDuplicates);
}

void ipmanipulatorSendDownstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard ipmanipulatorSendEgressMaybeSegmented(t, l, buf, ipmanipulatorSendDownstreamDuplicates, false, false);
}
