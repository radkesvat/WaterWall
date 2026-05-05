#include "trick.h"

#include "loggers/network_logger.h"

api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message);

enum
{
    kSynfinSniWarmupPackets             = 2,
    kSynfinSniIdleTimeoutMs             = 20U * 60U * 1000U,
    kSynfinSniGeneratedHelloMaxLen      = 900U,
    kSynfinSniMaxEmittedPackets         = 7U,
    kSynfinSniContinuationPreserveFlags = (TCP_CWR | TCP_ECE | TCP_URG | TCP_ACK)
};

typedef struct synfinsnitrick_tcp_packet_info_s
{
    const uint8_t *packet;
    uint32_t       seq;
    uint32_t       ack;
    uint16_t       payload_offset;
    uint16_t       ip_total_len;
    uint16_t       ip_header_len;
    uint16_t       tcp_header_len;
    uint16_t       headers_len;
    uint16_t       tcp_payload_len;
    uint16_t       src_port;
    uint16_t       dst_port;
    uint16_t       ip_identification;
    uint32_t       src_addr;
    uint32_t       dst_addr;
    uint8_t        tcp_flags;
} synfinsnitrick_tcp_packet_info_t;

typedef struct synfinsnitrick_packet_sequence_s
{
    sbuf_t *packets[kSynfinSniMaxEmittedPackets];
    uint16_t count;
} synfinsnitrick_packet_sequence_t;

static void synfinsnitrickFinalizePacketChecksum(sbuf_t *packet_buf, uint16_t ip_header_len, bool random_checksum)
{
    if (packet_buf == NULL)
    {
        return;
    }

    uint8_t *packet   = sbufGetMutablePtr(packet_buf);
    uint32_t pkt_len  = sbufGetLength(packet_buf);
    if (pkt_len < sizeof(struct ip_hdr))
    {
        return;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4)
    {
        return;
    }

    if (! random_checksum)
    {
        calcFullPacketChecksum(packet);
        return;
    }

    IPH_CHKSUM_SET(ipheader, (uint16_t) fastRand32());

    if (pkt_len < ip_header_len + sizeof(struct tcp_hdr))
    {
        return;
    }

    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + ip_header_len);
    tcp_header->chksum         = (uint16_t) fastRand32();
}

static sbuf_t *synfinsnitrickDuplicateStandalonePacket(const sbuf_t *source)
{
    uint32_t packet_len = sbufGetLength((sbuf_t *) source);
    sbuf_t  *copy       = sbufCreateWithPadding(packet_len, sbufGetLeftPadding((sbuf_t *) source));

    if (copy == NULL)
    {
        return NULL;
    }

    sbufSetLength(copy, packet_len);
    memoryCopyLarge(sbufGetMutablePtr(copy), sbufGetRawPtr((sbuf_t *) source), packet_len);
    return copy;
}

static void synfinsnitrickFillRandomBytes(uint8_t *dst, uint32_t len)
{
    if (dst == NULL || len == 0)
    {
        return;
    }

    uint32_t offset = 0;
    while (offset < len)
    {
        uint32_t rand_value = fastRand32();
        uint32_t copy_len   = min((uint32_t) sizeof(rand_value), len - offset);
        memoryCopy(dst + offset, &rand_value, copy_len);
        offset += copy_len;
    }
}

static void synfinsnitrickFillGeneratedTlsDataPayload(uint8_t *payload, uint32_t payload_len)
{
    if (payload == NULL || payload_len == 0)
    {
        return;
    }

    if (payload_len < 5U)
    {
        synfinsnitrickFillRandomBytes(payload, payload_len);
        return;
    }

    uint16_t record_payload_len = (uint16_t) (payload_len - 5U);

    payload[0] = 0x17;
    payload[1] = 0x03;
    payload[2] = 0x03;
    payload[3] = (uint8_t) (record_payload_len >> 8);
    payload[4] = (uint8_t) record_payload_len;

    synfinsnitrickFillRandomBytes(payload + 5U, record_payload_len);
}

static void synfinsnitrickDestroyCapturedPacket(ipmanipulator_captured_packet_t *packet)
{
    if (packet == NULL)
    {
        return;
    }

    if (packet->buf != NULL)
    {
        sbufDestroy(packet->buf);
    }

    packet->line = NULL;
    packet->buf  = NULL;
}

static void synfinsnitrickDestroyStandalonePacket(sbuf_t **packet)
{
    if (packet == NULL || *packet == NULL)
    {
        return;
    }

    sbufDestroy(*packet);
    *packet = NULL;
}

static void synfinsnitrickRecycleCapturedPacket(ipmanipulator_captured_packet_t *packet)
{
    if (packet == NULL)
    {
        return;
    }

    if (packet->line != NULL && packet->buf != NULL)
    {
        lineReuseBuffer(packet->line, packet->buf);
    }

    packet->line = NULL;
    packet->buf  = NULL;
}

static void synfinsnitrickDestroyPacketSequence(synfinsnitrick_packet_sequence_t *sequence)
{
    if (sequence == NULL)
    {
        return;
    }

    for (uint16_t i = 0; i < sequence->count; ++i)
    {
        if (sequence->packets[i] != NULL)
        {
            sbufDestroy(sequence->packets[i]);
            sequence->packets[i] = NULL;
        }
    }

    sequence->count = 0;
}

static void synfinsnitrickResetFlow(ipmanipulator_synfin_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    memoryZero(flow, sizeof(*flow));
}

static void synfinsnitrickDestroyFlow(ipmanipulator_synfin_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    synfinsnitrickDestroyCapturedPacket(&flow->held_packet);
    synfinsnitrickDestroyStandalonePacket(&flow->syn_packet_template);
    synfinsnitrickResetFlow(flow);
}

static void synfinsnitrickInitializeFlow(ipmanipulator_synfin_flow_t           *flow,
                                         const synfinsnitrick_tcp_packet_info_t *info, const sbuf_t *syn_packet_buf,
                                         uint64_t now_ms)
{
    sbuf_t *syn_packet_template = NULL;

    if (flow == NULL || info == NULL)
    {
        return;
    }

    if (syn_packet_buf != NULL)
    {
        syn_packet_template = synfinsnitrickDuplicateStandalonePacket(syn_packet_buf);
    }

    synfinsnitrickDestroyCapturedPacket(&flow->held_packet);
    synfinsnitrickDestroyStandalonePacket(&flow->syn_packet_template);
    synfinsnitrickResetFlow(flow);

    *flow = (ipmanipulator_synfin_flow_t) {
        .created_ms       = now_ms,
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .phase            = kIpManipulatorSynfinFlowPhaseWarmup,
        .active           = true,
        .syn_packet_template = syn_packet_template,
    };
}

static void synfinsnitrickFinalizeFlowLocked(ipmanipulator_synfin_flow_t *flow, bool block_flow)
{
    if (flow == NULL)
    {
        return;
    }

    synfinsnitrickDestroyCapturedPacket(&flow->held_packet);
    flow->warmup_packets_seen = kSynfinSniWarmupPackets;
    flow->phase               = block_flow ? kIpManipulatorSynfinFlowPhaseBlocked
                                           : kIpManipulatorSynfinFlowPhasePassthrough;
}

static bool synfinsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                             synfinsnitrick_tcp_packet_info_t *info)
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

    uint8_t ip_header_len_words = IPH_HL(ipheader);
    if (ip_header_len_words < 5 || ip_header_len_words > 15)
    {
        return false;
    }

    uint16_t ip_header_len = (uint16_t) (ip_header_len_words * 4U);
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

    const struct tcp_hdr *tcp_header       = (const struct tcp_hdr *) (packet + ip_header_len);
    uint8_t               tcp_header_words = TCPH_HDRLEN(tcp_header);
    if (tcp_header_words < 5 || tcp_header_words > 15)
    {
        return false;
    }

    uint16_t tcp_header_len = (uint16_t) (tcp_header_words * 4U);
    uint16_t headers_len    = (uint16_t) (ip_header_len + tcp_header_len);
    if (ip_total_len < headers_len)
    {
        return false;
    }

    *info = (synfinsnitrick_tcp_packet_info_t) {
        .packet            = packet,
        .seq               = lwip_ntohl(tcp_header->seqno),
        .ack               = lwip_ntohl(tcp_header->ackno),
        .payload_offset    = headers_len,
        .ip_total_len      = ip_total_len,
        .ip_header_len     = ip_header_len,
        .tcp_header_len    = tcp_header_len,
        .headers_len       = headers_len,
        .tcp_payload_len   = (uint16_t) (ip_total_len - headers_len),
        .src_port          = lwip_ntohs(tcp_header->src),
        .dst_port          = lwip_ntohs(tcp_header->dest),
        .ip_identification = lwip_ntohs(IPH_ID(ipheader)),
        .src_addr          = ipheader->src.addr,
        .dst_addr          = ipheader->dest.addr,
        .tcp_flags         = TCPH_FLAGS(tcp_header),
    };

    return true;
}

static bool synfinsnitrickIsPureSyn(const synfinsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && info->tcp_flags == TCP_SYN;
}

static bool synfinsnitrickHasFinOrRst(const synfinsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static bool synfinsnitrickFlowMatches(const ipmanipulator_synfin_flow_t      *flow,
                                      const synfinsnitrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr &&
           flow->src_port == info->src_port && flow->dst_port == info->dst_port;
}

static void synfinsnitrickCleanupIdleFlowsLocked(ipmanipulator_tstate_t *state, uint64_t now_ms)
{
    for (uint32_t i = 0; i < state->synfin_flows_capacity; ++i)
    {
        ipmanipulator_synfin_flow_t *flow = &state->synfin_flows[i];

        if (! flow->active)
        {
            continue;
        }

        if (now_ms - flow->last_activity_ms < kSynfinSniIdleTimeoutMs)
        {
            continue;
        }

        synfinsnitrickDestroyFlow(flow);
    }
}

static ipmanipulator_synfin_flow_t *synfinsnitrickFindFlowLocked(ipmanipulator_tstate_t                 *state,
                                                                 const synfinsnitrick_tcp_packet_info_t *info)
{
    for (uint32_t i = 0; i < state->synfin_flows_capacity; ++i)
    {
        if (synfinsnitrickFlowMatches(&state->synfin_flows[i], info))
        {
            return &state->synfin_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_synfin_flow_t *synfinsnitrickCreateFlowLocked(ipmanipulator_tstate_t                 *state,
                                                                   const synfinsnitrick_tcp_packet_info_t *info,
                                                                   const sbuf_t                           *syn_packet_buf,
                                                                   uint64_t                                 now_ms)
{
    for (uint32_t i = 0; i < state->synfin_flows_capacity; ++i)
    {
        ipmanipulator_synfin_flow_t *flow = &state->synfin_flows[i];

        if (flow->active)
        {
            continue;
        }

        synfinsnitrickInitializeFlow(flow, info, syn_packet_buf, now_ms);
        return flow;
    }

    uint32_t                     old_capacity = state->synfin_flows_capacity;
    uint32_t                     new_capacity = max(kIpManipulatorSmuggleInitialFlows, old_capacity * 2U);
    ipmanipulator_synfin_flow_t *grown =
        memoryReAllocate(state->synfin_flows, sizeof(*state->synfin_flows) * new_capacity);

    if (grown == NULL)
    {
        return NULL;
    }

    memoryZero(grown + old_capacity, sizeof(*grown) * (new_capacity - old_capacity));
    state->synfin_flows          = grown;
    state->synfin_flows_capacity = new_capacity;

    ipmanipulator_synfin_flow_t *flow = &state->synfin_flows[old_capacity];
    synfinsnitrickInitializeFlow(flow, info, syn_packet_buf, now_ms);
    return flow;
}

static sbuf_t *synfinsnitrickAllocateRequestBuffer(uint32_t len)
{
    buffer_pool_t *pool = getWorkerBufferPool(getWID());

    if (len <= bufferpoolGetSmallBufferSize(pool))
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (len <= bufferpoolGetLargeBufferSize(pool))
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreate(len);
}

static sbuf_t *synfinsnitrickGenerateTlsClientHello(tunnel_t *t)
{
    static const char kGenerateTlsHelloPrefix[] = "generateTlsHello:";

    ipmanipulator_tstate_t *state       = tunnelGetState(t);
    uint32_t                request_len =
        (uint32_t) (sizeof(kGenerateTlsHelloPrefix) - 1) + state->trick_synfin_sni_value_len;
    sbuf_t *request_buf = synfinsnitrickAllocateRequestBuffer(request_len);

    if (request_buf == NULL)
    {
        return NULL;
    }

    sbufSetLength(request_buf, request_len);
    memoryCopy(sbufGetMutablePtr(request_buf), kGenerateTlsHelloPrefix, sizeof(kGenerateTlsHelloPrefix) - 1);
    memoryCopy(sbufGetMutablePtr(request_buf) + (sizeof(kGenerateTlsHelloPrefix) - 1),
               state->trick_synfin_sni_value,
               state->trick_synfin_sni_value_len);

    api_result_t result = tlsclientTunnelApi(state->trick_synfin_sni_tls_client_tunnel, request_buf);

    if (result.result_code != kApiResultOk || result.buffer == NULL)
    {
        if (result.buffer != NULL)
        {
            reuseBuffer(result.buffer);
        }

        return NULL;
    }

    return result.buffer;
}

static sbuf_t *synfinsnitrickBuildCombinedPacket(line_t *l, const ipmanipulator_captured_packet_t *held_packet,
                                                 const synfinsnitrick_tcp_packet_info_t *held_info,
                                                 const synfinsnitrick_tcp_packet_info_t *current_info)
{
    if (l == NULL || held_packet == NULL || held_packet->buf == NULL || held_info == NULL || current_info == NULL)
    {
        return NULL;
    }

    uint32_t combined_payload_len = (uint32_t) held_info->tcp_payload_len + (uint32_t) current_info->tcp_payload_len;
    uint32_t combined_packet_len  = (uint32_t) held_info->headers_len + combined_payload_len;

    if (combined_packet_len > UINT16_MAX)
    {
        return NULL;
    }

    sbuf_t *combined = clonePacketWithLength(l, held_packet->buf, combined_packet_len);
    if (combined == NULL)
    {
        return NULL;
    }

    sbufSetLength(combined, combined_packet_len);

    uint8_t *packet = sbufGetMutablePtr(combined);
    memoryCopyLarge(packet, held_info->packet, held_info->headers_len);
    memoryCopyLarge(
        packet + held_info->headers_len, held_info->packet + held_info->payload_offset, held_info->tcp_payload_len);
    memoryCopyLarge(packet + held_info->headers_len + held_info->tcp_payload_len,
                    current_info->packet + current_info->payload_offset,
                    current_info->tcp_payload_len);

    struct ip_hdr *ipheader = (struct ip_hdr *) packet;
    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) combined_packet_len));
    IPH_OFFSET_SET(ipheader, lwip_htons((uint16_t) (lwip_ntohs(IPH_OFFSET(ipheader)) & ~(IP_MF | IP_OFFMASK))));

    return combined;
}

static sbuf_t *synfinsnitrickBuildPacketFromTemplate(line_t *l, sbuf_t *template_buf,
                                                     const synfinsnitrick_tcp_packet_info_t *template_info,
                                                     const uint8_t *payload, uint32_t payload_len, uint32_t seq,
                                                     uint16_t ip_identification, uint8_t tcp_flags)
{
    if (l == NULL || template_buf == NULL || template_info == NULL)
    {
        return NULL;
    }

    uint32_t packet_len = (uint32_t) template_info->headers_len + payload_len;
    if (packet_len > UINT16_MAX)
    {
        return NULL;
    }

    sbuf_t *result = clonePacketWithLength(l, template_buf, packet_len);
    if (result == NULL)
    {
        return NULL;
    }

    sbufSetLength(result, packet_len);

    uint8_t *packet = sbufGetMutablePtr(result);
    memoryCopyLarge(packet, template_info->packet, template_info->headers_len);
    if (payload_len > 0)
    {
        if (payload == NULL)
        {
            sbufDestroy(result);
            return NULL;
        }

        memoryCopyLarge(packet + template_info->headers_len, payload, payload_len);
    }

    struct ip_hdr  *ipheader  = (struct ip_hdr *) packet;
    struct tcp_hdr *tcpheader = (struct tcp_hdr *) (packet + template_info->ip_header_len);

    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) packet_len));
    IPH_ID_SET(ipheader, lwip_htons(ip_identification));
    IPH_OFFSET_SET(ipheader, lwip_htons((uint16_t) (lwip_ntohs(IPH_OFFSET(ipheader)) & ~(IP_MF | IP_OFFMASK))));
    tcpheader->seqno = lwip_htonl(seq);
    TCPH_FLAGS_SET(tcpheader, tcp_flags);

    return result;
}

static sbuf_t *synfinsnitrickBuildGeneratedTlsDataPacket(line_t *l,
                                                         const ipmanipulator_captured_packet_t *held_packet,
                                                         const synfinsnitrick_tcp_packet_info_t *held_info,
                                                         uint32_t payload_len, uint32_t seq,
                                                         uint16_t ip_identification, uint8_t tcp_flags)
{
    if (l == NULL || held_packet == NULL || held_packet->buf == NULL || held_info == NULL || payload_len == 0)
    {
        return NULL;
    }

    uint32_t packet_len = (uint32_t) held_info->headers_len + payload_len;
    if (packet_len > UINT16_MAX)
    {
        return NULL;
    }

    sbuf_t *packet = clonePacketWithLength(l, held_packet->buf, packet_len);
    if (packet == NULL)
    {
        return NULL;
    }

    sbufSetLength(packet, packet_len);

    uint8_t *raw_packet = sbufGetMutablePtr(packet);
    memoryCopyLarge(raw_packet, held_info->packet, held_info->headers_len);
    synfinsnitrickFillGeneratedTlsDataPayload(raw_packet + held_info->headers_len, payload_len);

    struct ip_hdr  *ipheader   = (struct ip_hdr *) raw_packet;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (raw_packet + held_info->ip_header_len);

    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) packet_len));
    IPH_ID_SET(ipheader, lwip_htons(ip_identification));
    IPH_OFFSET_SET(ipheader, lwip_htons((uint16_t) (lwip_ntohs(IPH_OFFSET(ipheader)) & ~(IP_MF | IP_OFFMASK))));
    tcp_header->seqno = lwip_htonl(seq);
    TCPH_FLAGS_SET(tcp_header, tcp_flags);
    tcp_header->urgp = 0;

    return packet;
}

static uint32_t synfinsnitrickChooseAdditionalPayloadLen(const ipmanipulator_tstate_t *state,
                                                         uint32_t generated_payload_len,
                                                         uint32_t real_payload_len,
                                                         uint32_t real_sni_payload_offset)
{
    if (state == NULL || real_payload_len <= generated_payload_len || real_sni_payload_offset <= generated_payload_len)
    {
        return 0;
    }

    uint32_t safe_max =
        min((uint32_t) state->trick_synfin_sni_additional_range_max,
            min(real_payload_len - generated_payload_len, real_sni_payload_offset - generated_payload_len));

    if (safe_max == 0)
    {
        return 0;
    }

    uint32_t safe_min = min((uint32_t) state->trick_synfin_sni_additional_range_min, safe_max);
    if (safe_min >= safe_max)
    {
        return safe_max;
    }

    return safe_min + (fastRand32() % (safe_max - safe_min + 1U));
}

static void synfinsnitrickApplyOptionalTtl(sbuf_t *packet_buf, int ttl_override)
{
    if (packet_buf == NULL || ttl_override < 0)
    {
        return;
    }

    uint8_t *packet = sbufGetMutablePtr(packet_buf);
    if (packet == NULL || sbufGetLength(packet_buf) < sizeof(struct ip_hdr))
    {
        return;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4)
    {
        return;
    }

    IPH_TTL_SET(ipheader, (uint8_t) ttl_override);
}

static sbuf_t *synfinsnitrickBuildFakeSynPacket(line_t *l, const sbuf_t *syn_packet_template,
                                                const ipmanipulator_captured_packet_t *held_packet,
                                                const ipmanipulator_tstate_t      *state,
                                                const synfinsnitrick_tcp_packet_info_t *held_info,
                                                uint16_t                                 ip_identification,
                                                uint32_t                                *syn_seq_out)
{
    synfinsnitrick_tcp_packet_info_t syn_template_info = {0};
    sbuf_t                          *source_template   = NULL;
    const synfinsnitrick_tcp_packet_info_t *source_info = NULL;

    if (l == NULL || held_packet == NULL || held_packet->buf == NULL || held_info == NULL || state == NULL)
    {
        return NULL;
    }

    if (syn_packet_template != NULL &&
        synfinsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr((sbuf_t *) syn_packet_template),
                                         sbufGetLength((sbuf_t *) syn_packet_template),
                                         &syn_template_info) &&
        synfinsnitrickIsPureSyn(&syn_template_info))
    {
        source_template = (sbuf_t *) syn_packet_template;
        source_info     = &syn_template_info;
    }
    else
    {
        source_template = held_packet->buf;
        source_info     = held_info;
    }

    sbuf_t *syn_packet = clonePacketWithLength(l, source_template, source_info->headers_len);
    if (syn_packet == NULL)
    {
        return NULL;
    }

    sbufSetLength(syn_packet, source_info->headers_len);
    memoryCopyLarge(sbufGetMutablePtr(syn_packet), source_info->packet, source_info->headers_len);

    uint8_t        *packet     = sbufGetMutablePtr(syn_packet);
    struct ip_hdr  *ipheader   = (struct ip_hdr *) packet;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + source_info->ip_header_len);

    IPH_LEN_SET(ipheader, lwip_htons(source_info->headers_len));
    IPH_ID_SET(ipheader, lwip_htons(ip_identification));
    IPH_OFFSET_SET(ipheader, lwip_htons((uint16_t) (lwip_ntohs(IPH_OFFSET(ipheader)) & ~(IP_MF | IP_OFFMASK))));

    if (state->trick_synfin_sni_syn_ttl >= 0)
    {
        IPH_TTL_SET(ipheader, (uint8_t) state->trick_synfin_sni_syn_ttl);
    }

    uint32_t syn_seq = 0;
    if (state->trick_synfin_sni_random_syn_sequence)
    {
        syn_seq = fastRand32();
    }
    else
    {
        syn_seq = held_info->seq - 1U;
    }

    tcp_header->seqno = lwip_htonl(syn_seq);
    tcp_header->ackno = 0;
    tcp_header->urgp  = 0;
    TCPH_FLAGS_SET(tcp_header, TCP_SYN);

    if (syn_seq_out != NULL)
    {
        *syn_seq_out = syn_seq;
    }

    synfinsnitrickFinalizePacketChecksum(syn_packet, source_info->ip_header_len,
                                         state->trick_synfin_sni_random_syn_checksum);

    return syn_packet;
}

static sbuf_t *synfinsnitrickBuildFakeClosePacket(line_t *l, const ipmanipulator_captured_packet_t *held_packet,
                                                  const ipmanipulator_tstate_t      *state,
                                                  const synfinsnitrick_tcp_packet_info_t *held_info,
                                                  uint32_t control_seq, uint16_t ip_identification)
{
    if (l == NULL || held_packet == NULL || held_packet->buf == NULL || held_info == NULL || state == NULL)
    {
        return NULL;
    }

    uint8_t control_flags = state->trick_synfin_sni_use_rst ? (TCP_RST | TCP_ACK) : (TCP_FIN | TCP_ACK);
    sbuf_t *packet        = synfinsnitrickBuildPacketFromTemplate(l,
                                                           held_packet->buf,
                                                           held_info,
                                                           NULL,
                                                           0,
                                                           control_seq,
                                                           ip_identification,
                                                           control_flags);
    if (packet == NULL)
    {
        return NULL;
    }

    uint8_t        *raw_packet = sbufGetMutablePtr(packet);
    struct ip_hdr  *ipheader   = (struct ip_hdr *) raw_packet;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (raw_packet + held_info->ip_header_len);

    if (state->trick_synfin_sni_fin_ttl >= 0)
    {
        IPH_TTL_SET(ipheader, (uint8_t) state->trick_synfin_sni_fin_ttl);
    }

    if (state->trick_synfin_sni_random_fin_sequence)
    {
        tcp_header->seqno = lwip_htonl(fastRand32());
    }
    tcp_header->urgp = 0;

    synfinsnitrickFinalizePacketChecksum(packet, held_info->ip_header_len,
                                         state->trick_synfin_sni_random_fin_checksum);
    return packet;
}

static bool synfinsnitrickAppendPacket(synfinsnitrick_packet_sequence_t *sequence, sbuf_t *packet)
{
    if (sequence == NULL || packet == NULL || sequence->count >= kSynfinSniMaxEmittedPackets)
    {
        return false;
    }

    sequence->packets[sequence->count++] = packet;
    return true;
}

static uint8_t synfinsnitrickGetContinuationFlags(uint8_t original_flags)
{
    return (uint8_t) (original_flags & kSynfinSniContinuationPreserveFlags);
}

static uint8_t synfinsnitrickGetFakePayloadFlags(uint8_t original_flags)
{
    return (uint8_t) (synfinsnitrickGetContinuationFlags(original_flags) | TCP_PSH);
}

static bool synfinsnitrickBuildPacketSequence(tunnel_t *t, line_t *l,
                                              const sbuf_t *syn_packet_template,
                                              const ipmanipulator_captured_packet_t *held_packet,
                                              const synfinsnitrick_tcp_packet_info_t *held_info, sbuf_t *current_buf,
                                              const synfinsnitrick_tcp_packet_info_t *current_info,
                                              const uint8_t *real_combined_payload, const uint8_t *generated_payload,
                                              uint32_t generated_payload_len, uint32_t packet_y_payload_len,
                                              synfinsnitrick_packet_sequence_t *sequence)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (l == NULL || held_packet == NULL || held_info == NULL || current_buf == NULL || current_info == NULL ||
        real_combined_payload == NULL || generated_payload == NULL || sequence == NULL || state == NULL)
    {
        return false;
    }

    uint32_t real_combined_payload_len =
        (uint32_t) held_info->tcp_payload_len + (uint32_t) current_info->tcp_payload_len;
    if (generated_payload_len == 0 || generated_payload_len > packet_y_payload_len ||
        packet_y_payload_len > real_combined_payload_len)
    {
        return false;
    }


    uint16_t next_ip_id = held_info->ip_identification;
    uint32_t close_seq  = held_info->seq + packet_y_payload_len;

    sbuf_t *packet_y = synfinsnitrickBuildPacketFromTemplate(l,
                                                             held_packet->buf,
                                                             held_info,
                                                             real_combined_payload,
                                                             packet_y_payload_len,
                                                             held_info->seq,
                                                             next_ip_id++,
                                                             held_info->tcp_flags);
    synfinsnitrickFinalizePacketChecksum(packet_y, held_info->ip_header_len, false);
    if (! synfinsnitrickAppendPacket(sequence, packet_y))
    {
        if (packet_y != NULL)
        {
            sbufDestroy(packet_y);
        }
        synfinsnitrickDestroyPacketSequence(sequence);
        return false;
    }

    sbuf_t *packet_fin =
        synfinsnitrickBuildFakeClosePacket(l, held_packet, state, held_info, close_seq, next_ip_id++);
    if (! synfinsnitrickAppendPacket(sequence, packet_fin))
    {
        if (packet_fin != NULL)
        {
            sbufDestroy(packet_fin);
        }
        synfinsnitrickDestroyPacketSequence(sequence);
        return false;
    }

    uint32_t syn_seq = 0;
    sbuf_t  *packet_syn =
        synfinsnitrickBuildFakeSynPacket(l, syn_packet_template, held_packet, state, held_info, next_ip_id++, &syn_seq);
    if (! synfinsnitrickAppendPacket(sequence, packet_syn))
    {
        if (packet_syn != NULL)
        {
            sbufDestroy(packet_syn);
        }
        synfinsnitrickDestroyPacketSequence(sequence);
        return false;
    }

    uint32_t generated_tail_payload_len = packet_y_payload_len - generated_payload_len;
    uint32_t fake_payload_seq           = held_info->seq;

    sbuf_t *packet_x = synfinsnitrickBuildPacketFromTemplate(l,
                                                             held_packet->buf,
                                                             held_info,
                                                             generated_payload,
                                                             generated_payload_len,
                                                             fake_payload_seq,
                                                             next_ip_id++,
                                                             synfinsnitrickGetFakePayloadFlags(held_info->tcp_flags));
    synfinsnitrickApplyOptionalTtl(packet_x, state->trick_synfin_sni_fake_ttl);
    synfinsnitrickFinalizePacketChecksum(packet_x, held_info->ip_header_len, false);
    if (! synfinsnitrickAppendPacket(sequence, packet_x))
    {
        if (packet_x != NULL)
        {
            sbufDestroy(packet_x);
        }
        synfinsnitrickDestroyPacketSequence(sequence);
        return false;
    }

    if (generated_tail_payload_len > 0)
    {
        sbuf_t *generated_tail = synfinsnitrickBuildGeneratedTlsDataPacket(l,
                                                                           held_packet,
                                                                           held_info,
                                                                           generated_tail_payload_len,
                                                                           fake_payload_seq + generated_payload_len,
                                                                           next_ip_id++,
                                                                           synfinsnitrickGetFakePayloadFlags(held_info->tcp_flags));
        synfinsnitrickFinalizePacketChecksum(generated_tail, held_info->ip_header_len, false);
        if (! synfinsnitrickAppendPacket(sequence, generated_tail))
        {
            if (generated_tail != NULL)
            {
                sbufDestroy(generated_tail);
            }
            synfinsnitrickDestroyPacketSequence(sequence);
            return false;
        }
    }

    uint32_t remaining_offset = packet_y_payload_len;
    uint32_t fourth_offset =
        remaining_offset > held_info->tcp_payload_len ? remaining_offset - held_info->tcp_payload_len : 0;
    bool have_fourth_tail = fourth_offset < current_info->tcp_payload_len;

    if (remaining_offset < held_info->tcp_payload_len)
    {
        uint32_t third_tail_len = held_info->tcp_payload_len - remaining_offset;
        uint8_t  third_tail_flags =
            have_fourth_tail ? synfinsnitrickGetContinuationFlags(held_info->tcp_flags) : held_info->tcp_flags;

        sbuf_t *third_tail = synfinsnitrickBuildPacketFromTemplate(l,
                                                                   held_packet->buf,
                                                                   held_info,
                                                                   real_combined_payload + remaining_offset,
                                                                   third_tail_len,
                                                                   held_info->seq + remaining_offset,
                                                                   next_ip_id++,
                                                                   third_tail_flags);
        synfinsnitrickFinalizePacketChecksum(third_tail, held_info->ip_header_len, false);
        if (! synfinsnitrickAppendPacket(sequence, third_tail))
        {
            if (third_tail != NULL)
            {
                sbufDestroy(third_tail);
            }
            synfinsnitrickDestroyPacketSequence(sequence);
            return false;
        }
    }

    if (have_fourth_tail)
    {
        uint32_t fourth_tail_len = current_info->tcp_payload_len - fourth_offset;
        sbuf_t  *fourth_tail =
            synfinsnitrickBuildPacketFromTemplate(l,
                                                  current_buf,
                                                  current_info,
                                                  real_combined_payload + held_info->tcp_payload_len + fourth_offset,
                                                  fourth_tail_len,
                                                  current_info->seq + fourth_offset,
                                                  next_ip_id++,
                                                  current_info->tcp_flags);
        synfinsnitrickFinalizePacketChecksum(fourth_tail, current_info->ip_header_len, false);
        if (! synfinsnitrickAppendPacket(sequence, fourth_tail))
        {
            if (fourth_tail != NULL)
            {
                sbufDestroy(fourth_tail);
            }
            synfinsnitrickDestroyPacketSequence(sequence);
            return false;
        }
    }

    return sequence->count >= (generated_tail_payload_len > 0 ? 5U : 4U);
}

static bool synfinsnitrickSendUpstreamDirectWithMode(tunnel_t *t, line_t *l, sbuf_t *buf, bool recalculate_checksum)
{
    if (t == NULL || l == NULL || buf == NULL)
    {
        return l != NULL ? lineIsAlive(l) : false;
    }

    if (! lineIsAlive(l))
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    bool ghost_applied = portghosttrickApply(t, l, &buf);
    if (buf == NULL)
    {
        return lineIsAlive(l);
    }

    lineSetRecalculateChecksum(l, recalculate_checksum || ghost_applied);
    tunnelNextUpStreamPayload(t, l, buf);
    return lineIsAlive(l);
}

static bool synfinsnitrickSendUpstreamDirect(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    return synfinsnitrickSendUpstreamDirectWithMode(t, l, buf, true);
}

static void synfinsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard synfinsnitrickSendUpstreamDirect(t, l, buf);
}

static void synfinsnitrickSendHeldThenCurrentNormal(tunnel_t *t, ipmanipulator_captured_packet_t *held_packet,
                                                    line_t *current_line, sbuf_t *current_buf)
{
    line_t *line = held_packet != NULL && held_packet->line != NULL ? held_packet->line : current_line;

    if (line == NULL)
    {
        if (held_packet != NULL)
        {
            synfinsnitrickDestroyCapturedPacket(held_packet);
        }

        if (current_buf != NULL)
        {
            sbufDestroy(current_buf);
        }

        return;
    }

    lineLock(line);

    bool alive = lineIsAlive(line);

    if (held_packet != NULL && held_packet->buf != NULL)
    {
        if (alive)
        {
            alive = synfinsnitrickSendUpstreamDirect(t, line, held_packet->buf);
        }
        else
        {
            lineReuseBuffer(line, held_packet->buf);
        }

        held_packet->line = NULL;
        held_packet->buf  = NULL;
    }

    if (current_buf != NULL)
    {
        if (alive)
        {
            discard synfinsnitrickSendUpstreamDirect(t, line, current_buf);
        }
        else
        {
            lineReuseBuffer(line, current_buf);
        }
    }

    lineUnlock(line);
}

static void synfinsnitrickSendOutputs(tunnel_t *t, line_t *l, synfinsnitrick_packet_sequence_t *sequence)
{
    if (l == NULL || sequence == NULL)
    {
        synfinsnitrickDestroyPacketSequence(sequence);
        return;
    }

    lineLock(l);

    bool alive = lineIsAlive(l);

    for (uint16_t i = 0; i < sequence->count; ++i)
    {
        sbuf_t *packet = sequence->packets[i];
        if (packet == NULL)
        {
            continue;
        }

        if (alive)
        {
            alive = synfinsnitrickSendUpstreamDirectWithMode(t, l, packet, false);
            wwSleepMS(20);
        }
        else
        {
            lineReuseBuffer(l, packet);
        }

        sequence->packets[i] = NULL;
    }

    sequence->count = 0;
    lineUnlock(l);
}

static void synfinsnitrickLogRejectedFlow(const sbuf_t *combined_packet, const sni_match_t *match,
                                          uint32_t real_sni_payload_offset, uint32_t generated_payload_len)
{
    const uint8_t *packet   = (const uint8_t *) sbufGetRawPtr((sbuf_t *) combined_packet);
    size_t         copy_len = min((size_t) match->sni_name_len, (size_t) 255U);
    char           sni_name[256];

    memoryZero(sni_name, sizeof(sni_name));
    memoryCopy(sni_name, packet + match->sni_name_offset, copy_len);

    LOGW("IpManipulator: synfin-sni rejected flow because real SNI \"%s\" begins at TLS payload offset %u before "
         "generated ClientHello length %u",
         sni_name,
         real_sni_payload_offset,
         generated_payload_len);
}

static bool synfinsnitrickHandleHeldPair(tunnel_t *t, line_t *l, ipmanipulator_captured_packet_t *held_packet,
                                         const sbuf_t *syn_packet_template, sbuf_t *current_buf,
                                         const synfinsnitrick_tcp_packet_info_t *current_info,
                                         bool *block_flow_out)
{
    ipmanipulator_tstate_t            *state     = tunnelGetState(t);
    synfinsnitrick_tcp_packet_info_t held_info = {0};

    if (block_flow_out != NULL)
    {
        *block_flow_out = false;
    }

    if (held_packet == NULL || held_packet->buf == NULL || held_packet->line == NULL || current_buf == NULL ||
        current_info == NULL)
    {
        if (held_packet != NULL)
        {
            synfinsnitrickRecycleCapturedPacket(held_packet);
        }

        if (current_buf != NULL)
        {
            synfinsnitrickSendNormalNow(t, l, current_buf);
        }

        return true;
    }

    if (! synfinsnitrickParseTcpPacketInfo(
            (const uint8_t *) sbufGetRawPtr(held_packet->buf), sbufGetLength(held_packet->buf), &held_info))
    {
        synfinsnitrickRecycleCapturedPacket(held_packet);
        synfinsnitrickSendNormalNow(t, l, current_buf);
        return true;
    }

    if ((uint32_t) current_info->seq != held_info.seq + (uint32_t) held_info.tcp_payload_len ||
        held_info.tcp_payload_len == 0 || current_info->tcp_payload_len == 0)
    {
        synfinsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *combined_packet = synfinsnitrickBuildCombinedPacket(held_packet->line, held_packet, &held_info, current_info);
    if (combined_packet == NULL)
    {
        synfinsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *generated_hello = synfinsnitrickGenerateTlsClientHello(t);
    if (generated_hello == NULL)
    {
        sbufDestroy(combined_packet);
        synfinsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    uint32_t generated_payload_len = sbufGetLength(generated_hello);
    uint32_t real_payload_len      = (uint32_t) held_info.tcp_payload_len + (uint32_t) current_info->tcp_payload_len;

    if (generated_payload_len == 0 || generated_payload_len > kSynfinSniGeneratedHelloMaxLen ||
        generated_payload_len > real_payload_len)
    {
        if (generated_payload_len > kSynfinSniGeneratedHelloMaxLen)
        {
            LOGW("IpManipulator: synfin-sni generated TLS ClientHello length %u exceeds supported limit %u",
                 generated_payload_len,
                 kSynfinSniGeneratedHelloMaxLen);
        }

        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        synfinsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sni_match_t match = {0};
    if (! parseClientHelloSni(
            (const uint8_t *) sbufGetRawPtr(combined_packet), sbufGetLength(combined_packet), &match) ||
        match.sni_name_offset < held_info.headers_len)
    {
        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        synfinsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    uint32_t real_sni_payload_offset = match.sni_name_offset - held_info.headers_len;
    if (real_sni_payload_offset < generated_payload_len)
    {
        synfinsnitrickLogRejectedFlow(combined_packet, &match, real_sni_payload_offset, generated_payload_len);

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        synfinsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    uint32_t additional_payload_len =
        synfinsnitrickChooseAdditionalPayloadLen(
            state, generated_payload_len, real_payload_len, real_sni_payload_offset);
    uint32_t packet_y_payload_len = generated_payload_len + additional_payload_len;

    synfinsnitrick_packet_sequence_t sequence = {0};
    const uint8_t                   *combined_payload =
        (const uint8_t *) sbufGetRawPtr(combined_packet) + held_info.headers_len;
    const uint8_t *generated_payload = (const uint8_t *) sbufGetRawPtr(generated_hello);

    if (! synfinsnitrickBuildPacketSequence(t,
                                            held_packet->line,
                                            syn_packet_template,
                                            held_packet,
                                            &held_info,
                                            current_buf,
                                            current_info,
                                            combined_payload,
                                            generated_payload,
                                            generated_payload_len,
                                            packet_y_payload_len,
                                            &sequence))
    {
        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        synfinsnitrickDestroyPacketSequence(&sequence);
        synfinsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    reuseBuffer(generated_hello);
    sbufDestroy(combined_packet);
    synfinsnitrickRecycleCapturedPacket(held_packet);
    lineReuseBuffer(l, current_buf);

    synfinsnitrickSendOutputs(t, l, &sequence);
    return true;
}

void synfinsnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->synfin_flows == NULL)
    {
        return;
    }

    mutexLock(&state->synfin_flows_mutex);

    for (uint32_t i = 0; i < state->synfin_flows_capacity; ++i)
    {
        synfinsnitrickDestroyFlow(&state->synfin_flows[i]);
    }

    mutexUnlock(&state->synfin_flows_mutex);
    mutexDestroy(&state->synfin_flows_mutex);

    memoryFree(state->synfin_flows);
    state->synfin_flows          = NULL;
    state->synfin_flows_capacity = 0;
}

bool synfinsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t          *state  = tunnelGetState(t);
    synfinsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                         now_ms = getTickMS();

    if (! synfinsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_captured_packet_t held_packet    = {0};
    bool                            bypass_current = false;
    sbuf_t                         *syn_packet_template = NULL;

    mutexLock(&state->synfin_flows_mutex);
    synfinsnitrickCleanupIdleFlowsLocked(state, now_ms);

    ipmanipulator_synfin_flow_t *flow = synfinsnitrickFindFlowLocked(state, &info);

    if (flow != NULL && synfinsnitrickIsPureSyn(&info))
    {
        synfinsnitrickInitializeFlow(flow, &info, buf, now_ms);
    }

    if (flow == NULL)
    {
        if (! synfinsnitrickIsPureSyn(&info))
        {
            mutexUnlock(&state->synfin_flows_mutex);
            return false;
        }

        flow = synfinsnitrickCreateFlowLocked(state, &info, buf, now_ms);
    }

    if (flow == NULL)
    {
        mutexUnlock(&state->synfin_flows_mutex);
        LOGW("IpManipulator: synfin-sni failed to allocate a flow record");
        return false;
    }

    flow->last_activity_ms = now_ms;

    if (flow->phase == kIpManipulatorSynfinFlowPhaseBlocked)
    {
        if (synfinsnitrickHasFinOrRst(&info))
        {
            synfinsnitrickDestroyFlow(flow);
        }

        mutexUnlock(&state->synfin_flows_mutex);
        lineReuseBuffer(l, buf);
        return true;
    }

    if (synfinsnitrickHasFinOrRst(&info))
    {
        if (flow->phase == kIpManipulatorSynfinFlowPhaseHoldThird)
        {
            held_packet       = flow->held_packet;
            flow->held_packet = (ipmanipulator_captured_packet_t) {0};
            bypass_current    = true;
        }

        synfinsnitrickDestroyFlow(flow);
        mutexUnlock(&state->synfin_flows_mutex);

        if (! bypass_current)
        {
            return false;
        }

        synfinsnitrickSendHeldThenCurrentNormal(t, &held_packet, l, buf);
        return true;
    }

    switch (flow->phase)
    {
    case kIpManipulatorSynfinFlowPhaseWarmup:
        if (flow->warmup_packets_seen < kSynfinSniWarmupPackets)
        {
            flow->warmup_packets_seen += 1;
            mutexUnlock(&state->synfin_flows_mutex);

            synfinsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        if (info.tcp_payload_len == 0)
        {
            flow->phase = kIpManipulatorSynfinFlowPhasePassthrough;
            mutexUnlock(&state->synfin_flows_mutex);

            synfinsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        flow->phase       = kIpManipulatorSynfinFlowPhaseHoldThird;
        flow->held_packet = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
        mutexUnlock(&state->synfin_flows_mutex);
        return true;

    case kIpManipulatorSynfinFlowPhasePassthrough:
        mutexUnlock(&state->synfin_flows_mutex);
        synfinsnitrickSendNormalNow(t, l, buf);
        return true;

    case kIpManipulatorSynfinFlowPhaseHoldThird: {
        bool block_flow = false;

        held_packet       = flow->held_packet;
        flow->held_packet = (ipmanipulator_captured_packet_t) {0};
        syn_packet_template = flow->syn_packet_template;

        mutexUnlock(&state->synfin_flows_mutex);

        bool handled = synfinsnitrickHandleHeldPair(t, l, &held_packet, syn_packet_template, buf, &info, &block_flow);

        mutexLock(&state->synfin_flows_mutex);
        flow = synfinsnitrickFindFlowLocked(state, &info);
        if (flow != NULL)
        {
            flow->last_activity_ms = getTickMS();
            synfinsnitrickFinalizeFlowLocked(flow, block_flow);
        }
        mutexUnlock(&state->synfin_flows_mutex);

        return handled;
    }

    case kIpManipulatorSynfinFlowPhaseBlocked:
    default:
        mutexUnlock(&state->synfin_flows_mutex);
        break;
    }

    return false;
}
