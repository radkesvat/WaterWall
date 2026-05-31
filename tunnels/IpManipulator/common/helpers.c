#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kIpManipulatorTlsCaptureTimeoutMs     = 1500,
    kIpManipulatorTlsPrestartTimeoutMs    = 50,
    kIpManipulatorTlsPrestartMinPayloadLen = 128,
    kIpManipulatorTlsCaptureMaxRecordLen  = 16384,

    kTcpFlagsPreservedOnSegmentContinuation = (TCP_CWR | TCP_ECE | TCP_URG | TCP_ACK)
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

typedef struct ipmanipulator_tls_clienthello_start_s
{
    ipmanipulator_tcp_packet_info_t tcp;
    uint32_t                        tls_record_total_len;
} ipmanipulator_tls_clienthello_start_t;

typedef enum ipmanipulator_tls_clienthello_start_status_e
{
    kIpManipulatorTlsClientHelloStartMiss = 0,
    kIpManipulatorTlsClientHelloStartComplete,
    kIpManipulatorTlsClientHelloStartFragmented,
    kIpManipulatorTlsClientHelloStartUnsupported
} ipmanipulator_tls_clienthello_start_status_t;

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
    default:
        return "unknown";
    }
}

static void ipmanipulatorResetCapturedSlot(ipmanipulator_tls_capture_slot_t *slot)
{
    memoryZero(slot, sizeof(*slot));
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

static void ipmanipulatorTakePrestartSlot(ipmanipulator_tls_prestart_slot_t *dest, ipmanipulator_tls_prestart_slot_t *src)
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

static void ipmanipulatorScheduleCapturedPacketNormal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    lineLock(l);
    sendWorkerMessageForceQueue(lineGetWID(l), (WorkerMessageCallback) ipmanipulatorReplayCapturedPacketOnWorker, t, l,
                                buf);
}

static void ipmanipulatorScheduleCapturedPacketReuse(line_t *l, sbuf_t *buf)
{
    lineLock(l);
    sendWorkerMessageForceQueue(lineGetWID(l), (WorkerMessageCallback) ipmanipulatorRecycleCapturedPacketOnWorker, l,
                                buf, NULL);
}

static void ipmanipulatorReleasePrestartPacketsNormal(tunnel_t *t, ipmanipulator_tls_prestart_slot_t *slot)
{
    if (slot == NULL)
    {
        return;
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

    ipmanipulatorResetPrestartSlot(slot);
}

static void ipmanipulatorReleasePendingPrestartOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t                                 *t     = arg1;
    ipmanipulator_tls_prestart_timeout_msg_t *msg   = arg2;
    ipmanipulator_tstate_t                   *state = tunnelGetState(t);
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

static void ipmanipulatorSchedulePrestartTimeout(tunnel_t *t, uint32_t slot_index, uint32_t generation)
{
    ipmanipulator_tls_prestart_timeout_msg_t *msg = memoryAllocate(sizeof(*msg));
    *msg = (ipmanipulator_tls_prestart_timeout_msg_t) {
        .slot_index  = slot_index,
        .generation  = generation,
    };

    sendWorkerMessageTimed(getWID(), (WorkerMessageCallback) ipmanipulatorReleasePendingPrestartOnWorker,
                           kIpManipulatorTlsPrestartTimeoutMs, t, msg, NULL);
}

void ipmanipulatorReleaseCapturedPacketsNormal(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot)
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
    if (packet_length < sizeof(struct ip_hdr))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4 || IPH_PROTO(ipheader) != IPPROTO_TCP)
    {
        return false;
    }

    uint8_t ip_hdr_len_words = IPH_HL(ipheader);
    if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
    {
        return false;
    }

    uint16_t ip_header_len = (uint16_t) (ip_hdr_len_words * 4);
    if (packet_length < ip_header_len + sizeof(struct tcp_hdr))
    {
        return false;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < ip_header_len + sizeof(struct tcp_hdr) || packet_length < ip_total_len)
    {
        return false;
    }

    uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
    if ((off_f & (IP_MF | IP_OFFMASK)) != 0)
    {
        return false;
    }

    const struct tcp_hdr *tcp_header        = (const struct tcp_hdr *) (packet + ip_header_len);
    uint8_t               tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
    if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
    {
        return false;
    }

    uint16_t tcp_header_len = (uint16_t) (tcp_hdr_len_words * 4);
    uint16_t headers_len    = (uint16_t) (ip_header_len + tcp_header_len);
    if (ip_total_len < headers_len)
    {
        return false;
    }

    *info = (ipmanipulator_tcp_packet_info_t) {
        .packet          = packet,
        .payload         = packet + headers_len,
        .seq             = lwip_ntohl(tcp_header->seqno),
        .src_addr        = ipheader->src.addr,
        .dst_addr        = ipheader->dest.addr,
        .ip_total_len    = ip_total_len,
        .ip_header_len   = ip_header_len,
        .tcp_header_len  = tcp_header_len,
        .headers_len     = headers_len,
        .tcp_payload_len = (uint16_t) (ip_total_len - headers_len),
        .src_port        = lwip_ntohs(tcp_header->src),
        .dst_port        = lwip_ntohs(tcp_header->dest),
    };

    return true;
}

static ipmanipulator_tls_clienthello_start_status_t
ipmanipulatorInspectTlsClientHelloStart(const uint8_t *packet, uint32_t packet_length,
                                        ipmanipulator_tls_clienthello_start_t *start)
{
    ipmanipulator_tcp_packet_info_t tcp = {0};

    if (! ipmanipulatorParseTcpPacketInfo(packet, packet_length, &tcp))
    {
        return kIpManipulatorTlsClientHelloStartMiss;
    }

    if (tcp.tcp_payload_len < 9)
    {
        return kIpManipulatorTlsClientHelloStartMiss;
    }

    if (tcp.payload[0] != 0x16 || tcp.payload[1] != 0x03 || tcp.payload[2] > 0x03 || tcp.payload[5] != 0x01)
    {
        return kIpManipulatorTlsClientHelloStartMiss;
    }

    uint16_t tls_record_len       = GET_BE16(tcp.payload + 3);
    uint32_t tls_record_total_len = 5U + (uint32_t) tls_record_len;
    uint32_t client_hello_len     = GET_BE24(tcp.payload + 6);

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

    if (tls_record_len == 0 || tls_record_total_len > kIpManipulatorTlsCaptureMaxRecordLen)
    {
        LOGD("IpManipulator: skipping oversized fragmented TLS ClientHello record (%u bytes)", tls_record_total_len);
        return kIpManipulatorTlsClientHelloStartUnsupported;
    }

    if (tls_record_total_len <= tcp.tcp_payload_len)
    {
        return kIpManipulatorTlsClientHelloStartComplete;
    }

    *start = (ipmanipulator_tls_clienthello_start_t) {
        .tcp                  = tcp,
        .tls_record_total_len = tls_record_total_len,
    };

    return kIpManipulatorTlsClientHelloStartFragmented;
}

static bool ipmanipulatorTlsCaptureSlotMatches(const ipmanipulator_tls_capture_slot_t *slot,
                                               const ipmanipulator_tcp_packet_info_t *info,
                                               ipmanipulator_tls_capture_kind_e kind)
{
    return slot->active && slot->kind == kind && slot->src_addr == info->src_addr && slot->dst_addr == info->dst_addr &&
           slot->src_port == info->src_port && slot->dst_port == info->dst_port;
}

static bool ipmanipulatorTlsPrestartSlotMatches(const ipmanipulator_tls_prestart_slot_t *slot,
                                                const ipmanipulator_tcp_packet_info_t *info,
                                                ipmanipulator_tls_capture_kind_e kind)
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
            ipmanipulatorParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(entry->buf), sbufGetLength(entry->buf), &info) &&
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
    slot->last_update_ms = getTickMS();
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

    uint32_t remaining = slot->tls_record_total_len - slot->tls_record_captured_len;
    if (remaining == 0)
    {
        return false;
    }

    if ((uint32_t) info->tcp_payload_len > remaining)
    {
        LOGD("IpManipulator: fragmented TLS ClientHello completed with %u extra TCP payload bytes in the same segment",
             (uint32_t) info->tcp_payload_len - remaining);
    }

    uint32_t new_payload_len = slot->captured_payload_len + info->tcp_payload_len;
    uint32_t new_packet_len  = slot->headers_len + new_payload_len;
    slot->assembled_packet   = sbufReserveSpace(slot->assembled_packet, new_packet_len);

    uint8_t *dest = sbufGetMutablePtr(slot->assembled_packet) + slot->headers_len + slot->captured_payload_len;
    memoryCopyLarge(dest, info->payload, info->tcp_payload_len);

    slot->captured_packets[slot->captured_packets_count++] = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
    slot->captured_payload_len = new_payload_len;
    slot->tls_record_captured_len += min((uint32_t) info->tcp_payload_len, remaining);
    slot->next_seq += info->tcp_payload_len;
    slot->last_update_ms = getTickMS();

    LOGD("IpManipulator: captured TLS ClientHello fragment payload=%u captured=%u/%u packets=%u",
         (unsigned int) info->tcp_payload_len,
         slot->tls_record_captured_len,
         slot->tls_record_total_len,
         (unsigned int) slot->captured_packets_count);

    if (slot->tls_record_captured_len == slot->tls_record_total_len)
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

static void ipmanipulatorDrainPrestartPacketsIntoCaptureSlot(ipmanipulator_tls_prestart_slot_t *prestart_slot,
                                                             ipmanipulator_tls_capture_slot_t *capture_slot, bool *complete)
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
                ! ipmanipulatorParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(entry->buf), sbufGetLength(entry->buf), &info) ||
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

static uint8_t ipmanipulatorGetSegmentFlags(uint8_t original_flags, uint32_t payload_offset, uint32_t this_payload_len,
                                            uint32_t total_payload_len)
{
    if (payload_offset == 0)
    {
        return original_flags;
    }

    if (payload_offset + this_payload_len < total_payload_len)
    {
        return (uint8_t) (original_flags & kTcpFlagsPreservedOnSegmentContinuation);
    }

    return original_flags;
}

static bool ipmanipulatorSendSinglePacketWithForward(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    lineSetRecalculateChecksum(l, true);
    forward(t, l, buf);
    return lineIsAlive(l);
}

bool ipmanipulatorSendWithForwardMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    discard portghosttrickApply(t, l, &buf);
    if (buf == NULL)
    {
        return lineIsAlive(l);
    }

    uint8_t *packet = sbufGetMutablePtr(buf);

    if (sbufGetLength(buf) < sizeof(struct ip_hdr))
    {
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4 || IPH_PROTO(ipheader) != IPPROTO_TCP)
    {
        return ipmanipulatorSendSinglePacketWithForward(t, l, buf, forward);
    }

    uint16_t ip_header_len = IPH_HL_BYTES(ipheader);
    if (sbufGetLength(buf) < ip_header_len + sizeof(struct tcp_hdr))
    {
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + ip_header_len);
    uint16_t        tcp_header_len = TCPH_HDRLEN_BYTES(tcp_header);
    uint32_t        headers_len    = (uint32_t) ip_header_len + (uint32_t) tcp_header_len;

    if (tcp_header_len < sizeof(struct tcp_hdr) || headers_len > sbufGetLength(buf))
    {
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < headers_len || ip_total_len > sbufGetLength(buf))
    {
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    if (ip_total_len <= GLOBAL_MTU_SIZE)
    {
        return ipmanipulatorSendSinglePacketWithForward(t, l, buf, forward);
    }

    if (GLOBAL_MTU_SIZE <= headers_len)
    {
        LOGW("IpManipulator: cannot segment crafted TLS packet because GLOBAL_MTU_SIZE (%u) is not larger than "
             "IPv4+TCP headers (%u)",
             GLOBAL_MTU_SIZE, headers_len);
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
    if ((off_f & (IP_MF | IP_OFFMASK)) != 0)
    {
        LOGW("IpManipulator: refusing TCP segmentation for an already fragmented IPv4 packet");
        reuseBuffer(buf);
        return lineIsAlive(l);
    }

    const uint8_t *source_payload      = packet + headers_len;
    uint32_t       total_payload_len   = (uint32_t) ip_total_len - headers_len;
    uint32_t       max_segment_payload = (uint32_t) GLOBAL_MTU_SIZE - headers_len;
    uint32_t       payload_offset      = 0;
    uint32_t       segment_index       = 0;
    uint32_t       base_seq            = lwip_ntohl(tcp_header->seqno);
    uint16_t       base_identification = lwip_ntohs(IPH_ID(ipheader));
    uint8_t        original_flags      = TCPH_FLAGS(tcp_header);
    bool           line_alive          = true;

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
        sbuf_t  *segment_buf      = clonePacketWithLength(l, buf, this_packet_len);

        if (segment_buf == NULL)
        {
            break;
        }

        sbufSetLength(segment_buf, this_packet_len);

        uint8_t *segment_packet = sbufGetMutablePtr(segment_buf);
        memoryCopyLarge(segment_packet, packet, headers_len);
        memoryCopyLarge(segment_packet + headers_len, source_payload + payload_offset, this_payload_len);

        struct ip_hdr  *segment_ipheader = (struct ip_hdr *) segment_packet;
        struct tcp_hdr *segment_tcpheader = (struct tcp_hdr *) (segment_packet + ip_header_len);

        IPH_LEN_SET(segment_ipheader, lwip_htons((uint16_t) this_packet_len));
        IPH_ID_SET(segment_ipheader, lwip_htons((uint16_t) (base_identification + (uint16_t) segment_index)));
        IPH_OFFSET_SET(segment_ipheader, lwip_htons(off_f & ~(IP_MF | IP_OFFMASK)));
        segment_tcpheader->seqno = lwip_htonl(base_seq + payload_offset);
        TCPH_FLAGS_SET(segment_tcpheader, ipmanipulatorGetSegmentFlags(original_flags, payload_offset,
                                                                       this_payload_len, total_payload_len));

        line_alive = ipmanipulatorSendSinglePacketWithForward(t, l, segment_buf, forward);
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

bool ipmanipulatorSendUpstreamMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    return ipmanipulatorSendWithForwardMaybeSegmented(t, l, buf, tunnelNextUpStreamPayload);
}

ipmanipulator_tls_capture_status_e ipmanipulatorCaptureTlsClientHello(
    tunnel_t *t, line_t *l, sbuf_t *buf, ipmanipulator_tls_capture_kind_e kind, ipmanipulator_tls_capture_slot_t *out_slot)
{
    ipmanipulator_tstate_t            *state = tunnelGetState(t);
    ipmanipulator_tcp_packet_info_t    info  = {0};
    ipmanipulator_tls_capture_slot_t   release_slot = {0};
    ipmanipulator_tls_prestart_slot_t  release_prestart_slot = {0};
    bool                               have_release = false;
    bool                               have_prestart_release = false;

    ipmanipulatorResetCapturedSlot(out_slot);

    if (! ipmanipulatorParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return kIpManipulatorTlsCaptureStatusMiss;
    }

    mutexLock(&state->tls_capture_mutex);

    uint64_t now_ms = getTickMS();
    int      matched_index = -1;
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

        if (ipmanipulatorTlsCaptureSlotMatches(slot, &info, kind))
        {
            matched_index = (int) i;
            break;
        }
    }

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

    if (matched_index >= 0)
    {
        ipmanipulator_tls_capture_slot_t *slot = &state->tls_capture_slots[matched_index];
        bool                              complete = false;
        bool                              appended = ipmanipulatorAppendPacketToCaptureSlot(slot, l, buf, &info, &complete);

        if (appended && prestart_index >= 0 && ! complete)
        {
            ipmanipulatorDrainPrestartPacketsIntoCaptureSlot(&state->tls_prestart_slots[prestart_index], slot, &complete);
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
        ipmanipulatorSendUpstreamFinal(t, l, buf);
        return kIpManipulatorTlsCaptureStatusBypassed;
    }

    ipmanipulator_tls_clienthello_start_t start = {0};
    ipmanipulator_tls_clienthello_start_status_t start_status =
        ipmanipulatorInspectTlsClientHelloStart((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &start);
    if (start_status != kIpManipulatorTlsClientHelloStartFragmented)
    {
        if (start_status == kIpManipulatorTlsClientHelloStartComplete ||
            start_status == kIpManipulatorTlsClientHelloStartUnsupported)
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

            if (oldest_prestart_index < 0 || slot->last_update_ms < state->tls_prestart_slots[oldest_prestart_index].last_update_ms)
            {
                oldest_prestart_index = (int) i;
            }
        }

        if (candidate_prestart_index < 0)
        {
            candidate_prestart_index = oldest_prestart_index;
            if (candidate_prestart_index >= 0 && ! have_prestart_release)
            {
                ipmanipulatorTakePrestartSlot(&release_prestart_slot, &state->tls_prestart_slots[candidate_prestart_index]);
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
    *slot = (ipmanipulator_tls_capture_slot_t) {
        .assembled_packet     = ipmanipulatorCreateStandalonePacketBuffer(buf, start.tcp.headers_len + start.tls_record_total_len),
        .last_update_ms       = now_ms,
        .next_seq             = start.tcp.seq,
        .tls_record_total_len = start.tls_record_total_len,
        .tls_record_captured_len = 0,
        .captured_payload_len = 0,
        .src_addr             = start.tcp.src_addr,
        .dst_addr             = start.tcp.dst_addr,
        .src_port             = start.tcp.src_port,
        .dst_port             = start.tcp.dst_port,
        .ip_header_len        = start.tcp.ip_header_len,
        .tcp_header_len       = start.tcp.tcp_header_len,
        .headers_len          = start.tcp.headers_len,
        .captured_packets_count = 0,
        .kind                 = kind,
        .active               = true,
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

    bool complete = false;
    bool appended = ipmanipulatorAppendPacketToCaptureSlot(slot, l, buf, &start.tcp, &complete);
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
    state->tls_capture_slots       = NULL;
    state->tls_capture_slots_count = 0;
    state->tls_prestart_slots      = NULL;
    state->tls_prestart_slots_count = 0;
}

sbuf_t *clonePacketWithLength(line_t *l, sbuf_t *buf, uint32_t new_len)
{
    buffer_pool_t *pool  = lineGetBufferPool(l);
    sbuf_t        *clone = NULL;

    if (new_len <= bufferpoolGetSmallBufferSize(pool))
    {
        clone = bufferpoolGetSmallBuffer(pool);
    }
    else if (new_len <= bufferpoolGetLargeBufferSize(pool))
    {
        clone = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        clone = sbufCreateWithPadding(new_len, sbufGetLeftPadding(buf));
    }

    sbufSetLength(clone, new_len);
    return clone;
}

bool parseClientHelloSni(const uint8_t *packet, uint32_t packet_length, sni_match_t *match)
{
    if (packet_length < sizeof(struct ip_hdr))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4 || IPH_PROTO(ipheader) != IPPROTO_TCP)
    {
        return false;
    }

    uint8_t ip_hdr_len_words = IPH_HL(ipheader);
    if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
    {
        LOGE("smugglesnitrick: invalid IP header length: %u", ip_hdr_len_words);
        return false;
    }

    uint16_t iphdr_len = (uint16_t) (ip_hdr_len_words * 4);
    if (packet_length < iphdr_len + sizeof(struct tcp_hdr))
    {
        return false;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < iphdr_len + sizeof(struct tcp_hdr) || packet_length < ip_total_len)
    {
        return false;
    }

    uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
    if ((off_f & IP_OFFMASK) != 0)
    {
        return false;
    }

    const struct tcp_hdr *tcp_header        = (const struct tcp_hdr *) (packet + iphdr_len);
    uint8_t               tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
    if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
    {
        LOGE("smugglesnitrick: invalid TCP header length: %u", tcp_hdr_len_words);
        return false;
    }

    uint16_t tcphdr_len = (uint16_t) (tcp_hdr_len_words * 4);
    if (ip_total_len < iphdr_len + tcphdr_len + 9)
    {
        return false;
    }

    const uint8_t *tls             = packet + iphdr_len + tcphdr_len;
    uint16_t       tcp_payload_len = (uint16_t) (ip_total_len - iphdr_len - tcphdr_len);
    if (tls[0] != 0x16 || tls[1] != 0x03 || tls[2] > 0x03)
    {
        return false;
    }

    uint16_t tls_record_len = GET_BE16(tls + 3);
    if ((uint32_t) tls_record_len + 5U > tcp_payload_len)
    {
        return false;
    }

    if (tls[5] != 0x01)
    {
        return false;
    }

    uint32_t client_hello_len = GET_BE24(tls + 6);
    if (client_hello_len < 34 || client_hello_len + 4U > tls_record_len)
    {
        return false;
    }

    const uint8_t *client_hello = tls + 9;
    const uint8_t *cursor       = client_hello + 34;
    const uint8_t *hello_end    = client_hello + client_hello_len;

    if (cursor >= hello_end)
    {
        return false;
    }

    uint8_t session_id_len = cursor[0];
    cursor += 1;
    if ((size_t) (hello_end - cursor) < session_id_len + 2U)
    {
        return false;
    }
    cursor += session_id_len;

    uint16_t cipher_suites_len = GET_BE16(cursor);
    cursor += 2;
    if ((size_t) (hello_end - cursor) < cipher_suites_len + 1U)
    {
        return false;
    }
    cursor += cipher_suites_len;

    uint8_t compression_methods_len = cursor[0];
    cursor += 1;
    if ((size_t) (hello_end - cursor) < compression_methods_len + 2U)
    {
        return false;
    }
    cursor += compression_methods_len;

    uint16_t extensions_len = GET_BE16(cursor);
    cursor += 2;
    if ((size_t) (hello_end - cursor) < extensions_len)
    {
        return false;
    }

    const uint8_t *extensions_end = cursor + extensions_len;
    bool           found_sni      = false;
    bool           has_psk_binder = false;

    while (cursor + 4 <= extensions_end)
    {
        uint16_t       extension_type = GET_BE16(cursor);
        uint16_t       extension_len  = GET_BE16(cursor + 2);
        const uint8_t *extension_data = cursor + 4;
        const uint8_t *next_extension = extension_data + extension_len;

        if (next_extension > extensions_end)
        {
            return false;
        }

        if (extension_type == 0x0000 && ! found_sni)
        {
            if (extension_len < 2)
            {
                return false;
            }

            uint16_t       server_name_list_len = GET_BE16(extension_data);
            const uint8_t *server_name_cursor   = extension_data + 2;
            const uint8_t *server_name_list_end = server_name_cursor + server_name_list_len;

            if (server_name_list_end > next_extension)
            {
                return false;
            }

            while (server_name_cursor + 3 <= server_name_list_end)
            {
                uint8_t        name_type = server_name_cursor[0];
                uint16_t       name_len  = GET_BE16(server_name_cursor + 1);
                const uint8_t *name_data = server_name_cursor + 3;
                const uint8_t *next_name = name_data + name_len;

                if (next_name > server_name_list_end)
                {
                    return false;
                }

                if (name_type == 0x00)
                {
                    *match = (sni_match_t) {
                        .ip_total_len                      = ip_total_len,
                        .tls_record_len                    = tls_record_len,
                        .client_hello_len                  = client_hello_len,
                        .has_tls13_psk_binder              = false,
                        .extensions_len                    = extensions_len,
                        .server_name_list_len              = server_name_list_len,
                        .server_name_ext_len               = extension_len,
                        .sni_name_len                      = name_len,
                        .sni_name_offset                   = (uint32_t) (name_data - packet),
                        .sni_name_len_field_offset         = (uint32_t) ((server_name_cursor + 1) - packet),
                        .extensions_len_field_offset       = (uint32_t) ((cursor - 2) - packet),
                        .server_name_list_len_field_offset = (uint32_t) (extension_data - packet),
                        .server_name_ext_len_field_offset  = (uint32_t) ((cursor + 2) - packet),
                        .tls_record_len_field_offset       = (uint32_t) ((tls + 3) - packet),
                        .client_hello_len_field_offset     = (uint32_t) ((tls + 6) - packet),
                    };
                    found_sni = true;
                    break;
                }

                server_name_cursor = next_name;
            }

            if (! found_sni)
            {
                return false;
            }
        }

        if (extension_type == 0x0029)
        {
            has_psk_binder = true;
        }

        cursor = next_extension;
    }

    if (! found_sni)
    {
        return false;
    }

    match->has_tls13_psk_binder = has_psk_binder;
    return true;
}

static void ipmanipulatorSendWithDuplicates(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward,
                                            bool apply_portghost)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    bool                    recalculate_checksum = lineGetRecalculateChecksum(l);
    bool                    ghost_applied        = false;

    if (apply_portghost)
    {
        ghost_applied = portghosttrickApply(t, l, &buf);
    }

    if (buf == NULL)
    {
        return;
    }

    recalculate_checksum = recalculate_checksum || ghost_applied;

    if (! state->trick_packet_duplicate || state->trick_packet_duplicate_count <= 0)
    {
        lineSetRecalculateChecksum(l, recalculate_checksum);
        forward(t, l, buf);
        return;
    }

    buffer_pool_t *pool                 = lineGetBufferPool(l);

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

void ipmanipulatorSendUpstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulatorSendWithDuplicates(t, l, buf, tunnelNextUpStreamPayload, true);
}

void ipmanipulatorSendDownstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulatorSendWithDuplicates(t, l, buf, tunnelPrevDownStreamPayload, false);
}
