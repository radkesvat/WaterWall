#include "trick.h"

#include "loggers/network_logger.h"

enum
{
    kEchSniWarmupPackets             = 2,
    kEchSniIdleTimeoutMs             = 20U * 60U * 1000U,
    kEchSniExtensionTypeServerName   = 0x0000U,
    kEchSniExtensionTypeEncryptedCH  = 0xFE0DU,
    kEchSniContinuationPreserveFlags = (TCP_CWR | TCP_ECE | TCP_URG | TCP_ACK)
};

typedef struct echsnitrick_tcp_packet_info_s
{
    const uint8_t *packet;
    uint32_t       seq;
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
} echsnitrick_tcp_packet_info_t;

typedef enum echsnitrick_clienthello_parse_status_e
{
    kEchSniClientHelloParseMiss = 0,
    kEchSniClientHelloParseMalformed,
    kEchSniClientHelloParseNoSni,
    kEchSniClientHelloParseReady
} echsnitrick_clienthello_parse_status_e;

typedef struct echsnitrick_clienthello_match_s
{
    uint32_t headers_len;

    uint32_t sni_extension_offset;
    uint16_t sni_extension_len;
    uint32_t sni_name_offset;
    uint16_t sni_name_len;

    uint32_t ech_extension_offset;
    uint16_t ech_extension_len;
    uint32_t ech_payload_offset;
    uint16_t ech_payload_len;

    bool has_ech;
    bool ech_before_sni;
} echsnitrick_clienthello_match_t;

typedef struct echsnitrick_delayed_release_s
{
    sbuf_t  *buf;
    sbuf_t  *next_buf;
    uint32_t next_delay_ms;
} echsnitrick_delayed_release_t;

static void echsnitrickDestroyCapturedPacket(ipmanipulator_captured_packet_t *packet)
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

static void echsnitrickRecycleCapturedPacket(ipmanipulator_captured_packet_t *packet)
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

static void echsnitrickDestroyStandalonePacket(sbuf_t **packet)
{
    if (packet == NULL || *packet == NULL)
    {
        return;
    }

    sbufDestroy(*packet);
    *packet = NULL;
}

static void echsnitrickResetFlow(ipmanipulator_echsni_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    memoryZero(flow, sizeof(*flow));
}

static void echsnitrickDestroyFlow(ipmanipulator_echsni_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    echsnitrickDestroyCapturedPacket(&flow->held_packet);
    echsnitrickResetFlow(flow);
}

static void echsnitrickInitializeFlow(ipmanipulator_echsni_flow_t *flow, const echsnitrick_tcp_packet_info_t *info,
                                      uint64_t now_ms)
{
    if (flow == NULL || info == NULL)
    {
        return;
    }

    echsnitrickDestroyCapturedPacket(&flow->held_packet);
    echsnitrickResetFlow(flow);

    *flow = (ipmanipulator_echsni_flow_t) {
        .created_ms       = now_ms,
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .phase            = kIpManipulatorEchSniFlowPhaseWarmup,
        .active           = true,
    };
}

static void echsnitrickFinalizeFlowLocked(ipmanipulator_echsni_flow_t *flow, bool block_flow, bool start_delay,
                                          uint64_t now_ms, const ipmanipulator_tstate_t *state)
{
    if (flow == NULL)
    {
        return;
    }

    echsnitrickDestroyCapturedPacket(&flow->held_packet);
    flow->warmup_packets_seen = kEchSniWarmupPackets;
    flow->phase = block_flow ? kIpManipulatorEchSniFlowPhaseBlocked : kIpManipulatorEchSniFlowPhasePassthrough;

    if (block_flow || ! start_delay || state == NULL)
    {
        flow->shard1_release_at_ms = 0;
        flow->shard2_release_at_ms = 0;
        return;
    }

    flow->shard1_release_at_ms = now_ms + state->trick_ech_sni_shard1_delay_ms;
    flow->shard2_release_at_ms = flow->shard1_release_at_ms + state->trick_ech_sni_shard2_delay_ms;
}

static uint8_t echsnitrickGetActiveDelayPhase(const ipmanipulator_echsni_flow_t *flow, uint64_t now_ms)
{
    if (flow == NULL || ! flow->active || flow->phase != kIpManipulatorEchSniFlowPhasePassthrough)
    {
        return 0;
    }

    if (now_ms < flow->shard1_release_at_ms)
    {
        return 1;
    }

    if (now_ms < flow->shard2_release_at_ms)
    {
        return 2;
    }

    return 0;
}

static bool echsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                          echsnitrick_tcp_packet_info_t *info)
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

    *info = (echsnitrick_tcp_packet_info_t) {
        .packet            = packet,
        .seq               = lwip_ntohl(tcp_header->seqno),
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

static bool echsnitrickIsPureSyn(const echsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && info->tcp_payload_len == 0 && info->tcp_flags == TCP_SYN;
}

static bool echsnitrickHasFinOrRst(const echsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static bool echsnitrickFlowMatches(const ipmanipulator_echsni_flow_t *flow, const echsnitrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr &&
           flow->src_port == info->src_port && flow->dst_port == info->dst_port;
}

static bool echsnitrickFlowMatchesReverse(const ipmanipulator_echsni_flow_t   *flow,
                                          const echsnitrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->dst_addr && flow->dst_addr == info->src_addr &&
           flow->src_port == info->dst_port && flow->dst_port == info->src_port;
}

static void echsnitrickCleanupIdleFlowsLocked(ipmanipulator_tstate_t *state, uint64_t now_ms)
{
    for (uint32_t i = 0; i < state->echsni_flows_capacity; ++i)
    {
        ipmanipulator_echsni_flow_t *flow = &state->echsni_flows[i];

        if (! flow->active)
        {
            continue;
        }

        if (now_ms - flow->last_activity_ms < kEchSniIdleTimeoutMs)
        {
            continue;
        }

        echsnitrickDestroyFlow(flow);
    }
}

static ipmanipulator_echsni_flow_t *echsnitrickFindFlowLocked(ipmanipulator_tstate_t              *state,
                                                              const echsnitrick_tcp_packet_info_t *info)
{
    for (uint32_t i = 0; i < state->echsni_flows_capacity; ++i)
    {
        if (echsnitrickFlowMatches(&state->echsni_flows[i], info))
        {
            return &state->echsni_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_echsni_flow_t *echsnitrickFindReverseFlowLocked(ipmanipulator_tstate_t              *state,
                                                                     const echsnitrick_tcp_packet_info_t *info)
{
    for (uint32_t i = 0; i < state->echsni_flows_capacity; ++i)
    {
        if (echsnitrickFlowMatchesReverse(&state->echsni_flows[i], info))
        {
            return &state->echsni_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_echsni_flow_t *echsnitrickCreateFlowLocked(ipmanipulator_tstate_t              *state,
                                                                const echsnitrick_tcp_packet_info_t *info,
                                                                uint64_t                             now_ms)
{
    for (uint32_t i = 0; i < state->echsni_flows_capacity; ++i)
    {
        ipmanipulator_echsni_flow_t *flow = &state->echsni_flows[i];

        if (flow->active)
        {
            continue;
        }

        echsnitrickInitializeFlow(flow, info, now_ms);
        return flow;
    }

    uint32_t                     old_capacity = state->echsni_flows_capacity;
    uint32_t                     new_capacity = max(kIpManipulatorSmuggleInitialFlows, old_capacity * 2U);
    ipmanipulator_echsni_flow_t *grown =
        memoryReAllocate(state->echsni_flows, sizeof(*state->echsni_flows) * new_capacity);

    if (grown == NULL)
    {
        return NULL;
    }

    memoryZero(grown + old_capacity, sizeof(*grown) * (new_capacity - old_capacity));
    state->echsni_flows          = grown;
    state->echsni_flows_capacity = new_capacity;

    ipmanipulator_echsni_flow_t *flow = &state->echsni_flows[old_capacity];
    echsnitrickInitializeFlow(flow, info, now_ms);
    return flow;
}

static echsnitrick_clienthello_parse_status_e echsnitrickParseClientHello(const uint8_t *packet, uint32_t packet_length,
                                                                          echsnitrick_clienthello_match_t *match)
{
    echsnitrick_tcp_packet_info_t tcp = {0};

    if (match != NULL)
    {
        memoryZero(match, sizeof(*match));
    }

    if (! echsnitrickParseTcpPacketInfo(packet, packet_length, &tcp))
    {
        return kEchSniClientHelloParseMiss;
    }

    if (tcp.tcp_payload_len < 9)
    {
        return kEchSniClientHelloParseMiss;
    }

    const uint8_t *tls = packet + tcp.payload_offset;
    if (tls[0] != 0x16 || tls[1] != 0x03 || tls[2] > 0x03 || tls[5] != 0x01)
    {
        return kEchSniClientHelloParseMiss;
    }

    uint16_t tls_record_len = GET_BE16(tls + 3);
    if ((uint32_t) tls_record_len + 5U > tcp.tcp_payload_len)
    {
        return kEchSniClientHelloParseMiss;
    }

    uint32_t client_hello_len = GET_BE24(tls + 6);
    if (client_hello_len < 34 || client_hello_len + 4U > tls_record_len)
    {
        return kEchSniClientHelloParseMalformed;
    }

    const uint8_t *client_hello = tls + 9;
    const uint8_t *cursor       = client_hello + 34;
    const uint8_t *hello_end    = client_hello + client_hello_len;

    if (cursor >= hello_end)
    {
        return kEchSniClientHelloParseMalformed;
    }

    uint8_t session_id_len = cursor[0];
    cursor += 1;
    if ((size_t) (hello_end - cursor) < session_id_len + 2U)
    {
        return kEchSniClientHelloParseMalformed;
    }
    cursor += session_id_len;

    uint16_t cipher_suites_len = GET_BE16(cursor);
    cursor += 2;
    if ((size_t) (hello_end - cursor) < cipher_suites_len + 1U)
    {
        return kEchSniClientHelloParseMalformed;
    }
    cursor += cipher_suites_len;

    uint8_t compression_methods_len = cursor[0];
    cursor += 1;
    if ((size_t) (hello_end - cursor) < compression_methods_len + 2U)
    {
        return kEchSniClientHelloParseMalformed;
    }
    cursor += compression_methods_len;

    uint16_t extensions_len = GET_BE16(cursor);
    cursor += 2;
    if ((size_t) (hello_end - cursor) < extensions_len)
    {
        return kEchSniClientHelloParseMalformed;
    }

    const uint8_t *extensions_end = cursor + extensions_len;
    bool           found_sni      = false;
    bool           found_ech      = false;
    uint32_t       extension_idx  = 0;
    uint32_t       sni_index      = 0;
    uint32_t       ech_index      = 0;

    while (cursor + 4 <= extensions_end)
    {
        uint16_t       extension_type = GET_BE16(cursor);
        uint16_t       extension_len  = GET_BE16(cursor + 2);
        const uint8_t *extension_data = cursor + 4;
        const uint8_t *next_extension = extension_data + extension_len;

        if (next_extension > extensions_end)
        {
            return kEchSniClientHelloParseMalformed;
        }

        if (extension_type == kEchSniExtensionTypeServerName && ! found_sni)
        {
            if (extension_len < 2)
            {
                return kEchSniClientHelloParseMalformed;
            }

            uint16_t       server_name_list_len = GET_BE16(extension_data);
            const uint8_t *server_name_cursor   = extension_data + 2;
            const uint8_t *server_name_list_end = server_name_cursor + server_name_list_len;

            if (server_name_list_end > next_extension)
            {
                return kEchSniClientHelloParseMalformed;
            }

            while (server_name_cursor + 3 <= server_name_list_end)
            {
                uint8_t        name_type = server_name_cursor[0];
                uint16_t       name_len  = GET_BE16(server_name_cursor + 1);
                const uint8_t *name_data = server_name_cursor + 3;
                const uint8_t *next_name = name_data + name_len;

                if (next_name > server_name_list_end)
                {
                    return kEchSniClientHelloParseMalformed;
                }

                if (name_type == 0x00)
                {
                    if (match != NULL)
                    {
                        match->headers_len          = tcp.headers_len;
                        match->sni_extension_offset = (uint32_t) (cursor - packet);
                        match->sni_extension_len    = extension_len;
                        match->sni_name_offset      = (uint32_t) (name_data - packet);
                        match->sni_name_len         = name_len;
                    }

                    found_sni = true;
                    sni_index = extension_idx;
                    break;
                }

                server_name_cursor = next_name;
            }

            if (! found_sni)
            {
                return kEchSniClientHelloParseNoSni;
            }
        }

        if (extension_type == kEchSniExtensionTypeEncryptedCH && ! found_ech)
        {
            if (extension_len < 10U)
            {
                return kEchSniClientHelloParseMalformed;
            }

            const uint8_t *ech_cursor = extension_data;
            uint8_t        ech_type   = *ech_cursor++;

            if (ech_type != 0x00)
            {
                return kEchSniClientHelloParseMalformed;
            }

            if ((size_t) (next_extension - ech_cursor) < 7U)
            {
                return kEchSniClientHelloParseMalformed;
            }

            ech_cursor += 2;
            ech_cursor += 2;
            ech_cursor += 1;

            uint16_t enc_len = GET_BE16(ech_cursor);
            ech_cursor += 2;
            if ((size_t) (next_extension - ech_cursor) < (size_t) enc_len + 2U)
            {
                return kEchSniClientHelloParseMalformed;
            }

            ech_cursor += enc_len;

            uint16_t payload_len = GET_BE16(ech_cursor);
            ech_cursor += 2;
            if ((size_t) (next_extension - ech_cursor) != payload_len)
            {
                return kEchSniClientHelloParseMalformed;
            }

            if (match != NULL)
            {
                match->ech_extension_offset = (uint32_t) (cursor - packet);
                match->ech_extension_len    = extension_len;
                match->ech_payload_offset   = (uint32_t) (ech_cursor - packet);
                match->ech_payload_len      = payload_len;
            }

            found_ech = true;
            ech_index = extension_idx;
        }

        cursor = next_extension;
        extension_idx += 1;
    }

    if (! found_sni)
    {
        return kEchSniClientHelloParseNoSni;
    }

    if (match != NULL)
    {
        match->has_ech        = found_ech;
        match->ech_before_sni = found_ech && ech_index < sni_index;
    }

    return kEchSniClientHelloParseReady;
}

static void echsnitrickCopySniName(const uint8_t *packet, const echsnitrick_clienthello_match_t *match, char *dst,
                                   size_t dst_size)
{
    if (dst == NULL || dst_size == 0)
    {
        return;
    }

    memoryZero(dst, dst_size);

    if (packet == NULL || match == NULL)
    {
        return;
    }

    size_t copy_len = min((size_t) match->sni_name_len, dst_size - 1U);
    memoryCopy(dst, packet + match->sni_name_offset, copy_len);
}

static bool echsnitrickFindInnerClientHello(const uint8_t *packet, uint32_t packet_length,
                                            const echsnitrick_clienthello_match_t *match, uint32_t *inner_offset_out,
                                            uint32_t *inner_len_out)
{
    if (packet == NULL || match == NULL || inner_offset_out == NULL || inner_len_out == NULL ||
        match->ech_payload_offset >= packet_length)
    {
        return false;
    }

    uint32_t payload_end = match->ech_payload_offset + (uint32_t) match->ech_payload_len;
    if (payload_end > packet_length || payload_end < match->ech_payload_offset)
    {
        return false;
    }

    const uint8_t *payload     = packet + match->ech_payload_offset;
    uint32_t       payload_len = (uint32_t) match->ech_payload_len;

    for (uint32_t offset = 0; offset + 9U <= payload_len; ++offset)
    {
        const uint8_t *tls = payload + offset;

        if (tls[0] != 0x16 || tls[1] != 0x03 || tls[2] > 0x03 || tls[5] != 0x01)
        {
            continue;
        }

        uint16_t tls_record_len = GET_BE16(tls + 3);
        uint32_t tls_total_len  = (uint32_t) tls_record_len + 5U;
        if (tls_total_len < 9U || offset + tls_total_len > payload_len)
        {
            continue;
        }

        uint32_t client_hello_len = GET_BE24(tls + 6);
        if (client_hello_len < 34U || client_hello_len + 4U > tls_record_len)
        {
            continue;
        }

        *inner_offset_out = match->ech_payload_offset + offset;
        *inner_len_out    = tls_total_len;
        return true;
    }

    return false;
}

static void echsnitrickLogDelayDiscard(const echsnitrick_tcp_packet_info_t *info, uint8_t phase)
{
    if (info == NULL)
    {
        return;
    }

    LOGW("IpManipulator: ech-sni-trick discarded an upstream packet on %u:%u -> %u:%u during original-release delay "
         "phase %u",
         info->src_addr,
         info->src_port,
         info->dst_addr,
         info->dst_port,
         (unsigned int) phase);
}

static sbuf_t *echsnitrickBuildCombinedPacket(line_t *l, const ipmanipulator_captured_packet_t *held_packet,
                                              const echsnitrick_tcp_packet_info_t *held_info,
                                              const echsnitrick_tcp_packet_info_t *current_info)
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

static sbuf_t *echsnitrickBuildPacketFromTemplate(line_t *l, sbuf_t *template_buf,
                                                  const echsnitrick_tcp_packet_info_t *template_info,
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

static uint8_t echsnitrickGetContinuationFlags(uint8_t original_flags)
{
    return (uint8_t) (original_flags & kEchSniContinuationPreserveFlags);
}

static uint8_t echsnitrickGetContinuationPushFlags(uint8_t original_flags)
{
    return (uint8_t) (echsnitrickGetContinuationFlags(original_flags) | TCP_PSH);
}

static void echsnitrickSelectTemplateForOffset(const ipmanipulator_captured_packet_t *held_packet,
                                               const echsnitrick_tcp_packet_info_t *held_info, sbuf_t *current_buf,
                                               const echsnitrick_tcp_packet_info_t *current_info,
                                               uint32_t payload_offset, sbuf_t **template_buf,
                                               const echsnitrick_tcp_packet_info_t **template_info)
{
    if (template_buf == NULL || template_info == NULL || held_packet == NULL || held_info == NULL ||
        current_buf == NULL || current_info == NULL)
    {
        return;
    }

    if (payload_offset >= held_info->tcp_payload_len)
    {
        *template_buf  = current_buf;
        *template_info = current_info;
        return;
    }

    *template_buf  = held_packet->buf;
    *template_info = held_info;
}

static bool echsnitrickSendUpstreamDirect(tunnel_t *t, line_t *l, sbuf_t *buf)
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

    discard portghosttrickApply(t, l, &buf);
    if (buf == NULL)
    {
        return lineIsAlive(l);
    }

    lineSetRecalculateChecksum(l, true);
    tunnelNextUpStreamPayload(t, l, buf);
    return lineIsAlive(l);
}

static bool echsnitrickScheduleOriginalReleasePacket(tunnel_t *t, line_t *l, sbuf_t *buf, sbuf_t *next_buf,
                                                     uint32_t delay_ms, uint32_t next_delay_ms);

static void echsnitrickRunDelayedOriginalRelease(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;

    tunnel_t                      *t       = arg1;
    line_t                        *l       = arg2;
    echsnitrick_delayed_release_t *release = arg3;
    bool                           alive   = lineIsAlive(l);

    if (release != NULL && release->buf != NULL)
    {
        if (alive)
        {
            alive = echsnitrickSendUpstreamDirect(t, l, release->buf);
        }
        else
        {
            lineReuseBuffer(l, release->buf);
        }
    }

    if (release != NULL && release->next_buf != NULL)
    {
        if (alive)
        {
            discard echsnitrickScheduleOriginalReleasePacket(t, l, release->next_buf, NULL, release->next_delay_ms, 0);
        }
        else
        {
            lineReuseBuffer(l, release->next_buf);
        }
    }

    if (release != NULL)
    {
        memoryFree(release);
    }

    lineUnlock(l);
}

static void echsnitrickCleanupDelayedBuffer(line_t *l, sbuf_t *buf)
{
    if (buf == NULL)
    {
        return;
    }

    if (getWID() == lineGetWID(l))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    sbufDestroy(buf);
}

static void echsnitrickCleanupDelayedOriginalRelease(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    line_t                        *l       = arg2;
    echsnitrick_delayed_release_t *release = arg3;

    if (release != NULL)
    {
        if (release->buf != NULL)
        {
            echsnitrickCleanupDelayedBuffer(l, release->buf);
        }
        if (release->next_buf != NULL)
        {
            echsnitrickCleanupDelayedBuffer(l, release->next_buf);
        }
        memoryFree(release);
    }

    lineUnlock(l);
}

static bool echsnitrickScheduleOriginalReleasePacket(tunnel_t *t, line_t *l, sbuf_t *buf, sbuf_t *next_buf,
                                                     uint32_t delay_ms, uint32_t next_delay_ms)
{
    if (t == NULL || l == NULL)
    {
        if (buf != NULL)
        {
            sbufDestroy(buf);
        }

        if (next_buf != NULL)
        {
            sbufDestroy(next_buf);
        }

        return l != NULL ? lineIsAlive(l) : false;
    }

    if (! lineIsAlive(l))
    {
        if (buf != NULL)
        {
            lineReuseBuffer(l, buf);
        }

        if (next_buf != NULL)
        {
            lineReuseBuffer(l, next_buf);
        }

        return false;
    }

    if (delay_ms == 0 && getWID() == lineGetWID(l))
    {
        bool alive = lineIsAlive(l);

        if (buf != NULL)
        {
            alive = echsnitrickSendUpstreamDirect(t, l, buf);
        }

        if (next_buf != NULL)
        {
            if (alive)
            {
                discard echsnitrickScheduleOriginalReleasePacket(t, l, next_buf, NULL, next_delay_ms, 0);
            }
            else
            {
                lineReuseBuffer(l, next_buf);
            }
        }

        return alive;
    }

    echsnitrick_delayed_release_t *release = memoryAllocate(sizeof(*release));
    *release                               = (echsnitrick_delayed_release_t) {
                                      .buf           = buf,
                                      .next_buf      = next_buf,
                                      .next_delay_ms = next_delay_ms,
    };

    lineLock(l);
    sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                      (WorkerMessageCallback) echsnitrickRunDelayedOriginalRelease,
                                      echsnitrickCleanupDelayedOriginalRelease,
                                      delay_ms,
                                      t,
                                      l,
                                      release);
    return lineIsAlive(l);
}

static bool echsnitrickScheduleOriginalRelease(tunnel_t *t, line_t *l, sbuf_t *held_buf, sbuf_t *current_buf,
                                               uint32_t shard1_delay_ms, uint32_t shard2_delay_ms)
{
    if (held_buf == NULL)
    {
        return echsnitrickScheduleOriginalReleasePacket(t, l, current_buf, NULL, shard1_delay_ms, 0);
    }

    return echsnitrickScheduleOriginalReleasePacket(t, l, held_buf, current_buf, shard1_delay_ms, shard2_delay_ms);
}

static void echsnitrickSendInnerThenOriginalDelayed(tunnel_t *t, line_t *l, sbuf_t *inner_packet,
                                                    ipmanipulator_captured_packet_t *held_packet, sbuf_t *current_buf,
                                                    uint32_t shard1_delay_ms, uint32_t shard2_delay_ms)
{
    line_t *line = held_packet != NULL && held_packet->line != NULL ? held_packet->line : l;

    if (line == NULL)
    {
        echsnitrickDestroyStandalonePacket(&inner_packet);
        if (held_packet != NULL)
        {
            echsnitrickDestroyCapturedPacket(held_packet);
        }

        if (current_buf != NULL)
        {
            sbufDestroy(current_buf);
        }

        return;
    }

    sbuf_t *held_buf = NULL;
    if (held_packet != NULL)
    {
        held_buf          = held_packet->buf;
        held_packet->line = NULL;
        held_packet->buf  = NULL;
    }

    lineLock(line);

    bool alive = lineIsAlive(line);

    if (inner_packet != NULL)
    {
        if (alive)
        {
            alive = echsnitrickSendUpstreamDirect(t, line, inner_packet);
        }
        else
        {
            lineReuseBuffer(line, inner_packet);
        }
        inner_packet = NULL;
    }

    if (held_buf != NULL || current_buf != NULL)
    {
        if (alive)
        {
            discard echsnitrickScheduleOriginalRelease(
                t, line, held_buf, current_buf, shard1_delay_ms, shard2_delay_ms);
        }
        else
        {
            if (held_buf != NULL)
            {
                lineReuseBuffer(line, held_buf);
            }

            if (current_buf != NULL)
            {
                lineReuseBuffer(line, current_buf);
            }
        }
    }

    lineUnlock(line);
}

static void echsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard echsnitrickSendUpstreamDirect(t, l, buf);
}

static void echsnitrickSendHeldThenCurrentNormal(tunnel_t *t, ipmanipulator_captured_packet_t *held_packet,
                                                 line_t *current_line, sbuf_t *current_buf)
{
    line_t *line = held_packet != NULL && held_packet->line != NULL ? held_packet->line : current_line;

    if (line == NULL)
    {
        if (held_packet != NULL)
        {
            echsnitrickDestroyCapturedPacket(held_packet);
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
            alive = echsnitrickSendUpstreamDirect(t, line, held_packet->buf);
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
            discard echsnitrickSendUpstreamDirect(t, line, current_buf);
        }
        else
        {
            lineReuseBuffer(line, current_buf);
        }
    }

    lineUnlock(line);
}

static void echsnitrickLogMissingSniReject(void)
{
    LOGW("IpManipulator: ech-sni-trick rejected flow because the TLS ClientHello has no usable SNI extension");
}

static void echsnitrickLogMalformedReject(void)
{
    LOGW("IpManipulator: ech-sni-trick rejected flow because the TLS ClientHello extensions are malformed");
}

static void echsnitrickLogMissingEchReject(const char *sni_name)
{
    LOGW("IpManipulator: ech-sni-trick rejected flow because TLS ClientHello for SNI \"%s\" does not contain the "
         "encrypted_client_hello extension",
         sni_name);
}

static void echsnitrickLogMissingInnerReject(const char *sni_name)
{
    LOGW("IpManipulator: ech-sni-trick rejected flow because the ECH payload for SNI \"%s\" does not contain a fake "
         "TLS ClientHello",
         sni_name);
}

static void echsnitrickLogInnerMtuReject(const char *sni_name, uint32_t inner_len, uint32_t packet_len)
{
    LOGW("IpManipulator: ech-sni-trick rejected flow because fake inner ClientHello for \"%s\" is %u bytes and would "
         "create a %u-byte TCP packet, exceeding GLOBAL_MTU_SIZE %u",
         sni_name,
         inner_len,
         packet_len,
         GLOBAL_MTU_SIZE);
}

static void echsnitrickLogPairCapture(const echsnitrick_tcp_packet_info_t *held_info,
                                      const echsnitrick_tcp_packet_info_t *current_info)
{
    if (held_info == NULL || current_info == NULL)
    {
        return;
    }

    LOGD("IpManipulator: ech-sni-trick combining held packet payload=%u seq=%u with next payload=%u seq=%u",
         held_info->tcp_payload_len,
         held_info->seq,
         current_info->tcp_payload_len,
         current_info->seq);
}

static void echsnitrickLogParseMissPassthrough(uint32_t combined_payload_len)
{
    LOGD("IpManipulator: ech-sni-trick forwarded the held packet unchanged because the combined TCP payload (%u bytes) "
         "was not a complete parseable TLS ClientHello",
         combined_payload_len);
}

static void echsnitrickLogCandidateMatch(const char *sni_name, const echsnitrick_clienthello_match_t *match,
                                         uint32_t inner_offset, uint32_t inner_len)
{
    if (sni_name == NULL || match == NULL)
    {
        return;
    }

    LOGD("IpManipulator: ech-sni-trick matched SNI \"%s\" with ECH ext offset=%u payload offset=%u SNI ext offset=%u "
         "payload_len=%u inner_offset=%u inner_len=%u",
         sni_name,
         match->ech_extension_offset,
         match->ech_payload_offset,
         match->sni_extension_offset,
         match->ech_payload_len,
         inner_offset,
         inner_len);
}

static void echsnitrickLogCraftedSuccess(const char *original_sni, const char *replacement_sni,
                                         const echsnitrick_clienthello_match_t *match, uint32_t inner_stream_offset,
                                         uint32_t inner_payload_len, uint32_t shard1_delay_ms, uint32_t shard2_delay_ms)
{
    if (original_sni == NULL || replacement_sni == NULL || match == NULL)
    {
        return;
    }

    LOGD("IpManipulator: ech-sni-trick sent fake inner ClientHello for \"%s\" out of order using existing ECH payload "
         "bytes (configured replacement \"%s\") (ech_offset=%u sni_offset=%u inner_stream_offset=%u inner_len=%u "
         "shard1_delay=%u shard2_delay=%u)",
         original_sni,
         replacement_sni,
         match->ech_extension_offset,
         match->sni_extension_offset,
         inner_stream_offset,
         inner_payload_len,
         shard1_delay_ms,
         shard2_delay_ms);
}

static void echsnitrickLogRetransmitStandaloneAttempt(const echsnitrick_tcp_packet_info_t *held_info)
{
    if (held_info == NULL)
    {
        return;
    }

    LOGD("IpManipulator: ech-sni-trick saw a retransmission of the held packet seq=%u payload=%u and will attempt a "
         "held-only ClientHello craft",
         held_info->seq,
         held_info->tcp_payload_len);
}

static void echsnitrickLogSequenceMismatchPassthrough(uint32_t expected_seq, uint32_t actual_seq)
{
    LOGD("IpManipulator: ech-sni-trick forwarded the held packet unchanged because it expected next seq=%u but saw "
         "seq=%u",
         expected_seq,
         actual_seq);
}

static bool echsnitrickIsHeldPayloadRetransmit(const echsnitrick_tcp_packet_info_t *held_info,
                                               const echsnitrick_tcp_packet_info_t *current_info)
{
    if (held_info == NULL || current_info == NULL || held_info->tcp_payload_len == 0 ||
        held_info->tcp_payload_len != current_info->tcp_payload_len || held_info->seq != current_info->seq)
    {
        return false;
    }

    return memoryCompare(held_info->packet + held_info->payload_offset,
                         current_info->packet + current_info->payload_offset,
                         held_info->tcp_payload_len) == 0;
}

static sbuf_t *echsnitrickCloneStandalonePacket(line_t *l, const ipmanipulator_captured_packet_t *held_packet,
                                                const echsnitrick_tcp_packet_info_t *held_info)
{
    if (l == NULL || held_packet == NULL || held_packet->buf == NULL || held_info == NULL)
    {
        return NULL;
    }

    uint32_t packet_len = (uint32_t) held_info->headers_len + held_info->tcp_payload_len;
    sbuf_t  *clone      = clonePacketWithLength(l, held_packet->buf, packet_len);
    if (clone == NULL)
    {
        return NULL;
    }

    sbufSetLength(clone, packet_len);
    memoryCopyLarge(sbufGetMutablePtr(clone), held_info->packet, packet_len);
    return clone;
}

static bool echsnitrickHandleHeldStandalone(tunnel_t *t, line_t *l, ipmanipulator_captured_packet_t *held_packet,
                                            sbuf_t *current_buf, const echsnitrick_tcp_packet_info_t *held_info,
                                            bool *block_flow_out, bool *start_delay_out)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (block_flow_out != NULL)
    {
        *block_flow_out = false;
    }

    if (start_delay_out != NULL)
    {
        *start_delay_out = false;
    }

    if (held_packet == NULL || held_packet->buf == NULL || held_packet->line == NULL || held_info == NULL)
    {
        if (held_packet != NULL)
        {
            echsnitrickRecycleCapturedPacket(held_packet);
        }

        if (current_buf != NULL)
        {
            lineReuseBuffer(l, current_buf);
        }

        return true;
    }

    sbuf_t *combined_packet = echsnitrickCloneStandalonePacket(held_packet->line, held_packet, held_info);
    if (combined_packet == NULL)
    {
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    echsnitrick_clienthello_match_t        match        = {0};
    echsnitrick_clienthello_parse_status_e parse_status = echsnitrickParseClientHello(
        (const uint8_t *) sbufGetRawPtr(combined_packet), sbufGetLength(combined_packet), &match);

    if (parse_status == kEchSniClientHelloParseMiss)
    {
        echsnitrickLogParseMissPassthrough((uint32_t) held_info->tcp_payload_len);
        sbufDestroy(combined_packet);
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    if (parse_status == kEchSniClientHelloParseMalformed)
    {
        echsnitrickLogMalformedReject();

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        if (current_buf != NULL)
        {
            lineReuseBuffer(l, current_buf);
        }
        return true;
    }

    if (parse_status == kEchSniClientHelloParseNoSni)
    {
        echsnitrickLogMissingSniReject();

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        if (current_buf != NULL)
        {
            lineReuseBuffer(l, current_buf);
        }
        return true;
    }

    char           sni_name[256];
    const uint8_t *combined_packet_bytes = (const uint8_t *) sbufGetRawPtr(combined_packet);
    echsnitrickCopySniName(combined_packet_bytes, &match, sni_name, sizeof(sni_name));

    if (! match.has_ech)
    {
        echsnitrickLogMissingEchReject(sni_name);

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        if (current_buf != NULL)
        {
            lineReuseBuffer(l, current_buf);
        }
        return true;
    }

    uint32_t inner_offset = 0;
    uint32_t inner_len    = 0;
    if (! echsnitrickFindInnerClientHello(
            combined_packet_bytes, sbufGetLength(combined_packet), &match, &inner_offset, &inner_len))
    {
        echsnitrickLogMissingInnerReject(sni_name);

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        if (current_buf != NULL)
        {
            lineReuseBuffer(l, current_buf);
        }
        return true;
    }

    echsnitrickLogCandidateMatch(sni_name, &match, inner_offset, inner_len);

    uint32_t total_payload_len   = (uint32_t) held_info->tcp_payload_len;
    uint32_t inner_stream_offset = inner_offset - match.headers_len;

    if (inner_offset < match.headers_len || inner_stream_offset >= total_payload_len ||
        inner_len > total_payload_len - inner_stream_offset)
    {
        echsnitrickLogMalformedReject();

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        if (current_buf != NULL)
        {
            lineReuseBuffer(l, current_buf);
        }
        return true;
    }

    const uint8_t *combined_payload = ((const uint8_t *) sbufGetRawPtr(combined_packet)) + held_info->headers_len;
    uint32_t       packet_len       = (uint32_t) held_info->headers_len + inner_len;
    if (packet_len > GLOBAL_MTU_SIZE)
    {
        echsnitrickLogInnerMtuReject(sni_name, inner_len, packet_len);

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        if (current_buf != NULL)
        {
            lineReuseBuffer(l, current_buf);
        }
        return true;
    }

    uint8_t inner_flags  = echsnitrickGetContinuationPushFlags(held_info->tcp_flags);
    sbuf_t *inner_packet = echsnitrickBuildPacketFromTemplate(held_packet->line,
                                                              held_packet->buf,
                                                              held_info,
                                                              combined_payload + inner_stream_offset,
                                                              inner_len,
                                                              held_info->seq + inner_stream_offset,
                                                              held_info->ip_identification,
                                                              inner_flags);

    if (inner_packet == NULL)
    {
        sbufDestroy(combined_packet);
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbufDestroy(combined_packet);
    if (current_buf != NULL)
    {
        lineReuseBuffer(l, current_buf);
        current_buf = NULL;
    }

    echsnitrickSendInnerThenOriginalDelayed(t,
                                            l,
                                            inner_packet,
                                            held_packet,
                                            current_buf,
                                            state->trick_ech_sni_shard1_delay_ms,
                                            state->trick_ech_sni_shard2_delay_ms);
    echsnitrickLogCraftedSuccess(sni_name,
                                 state->trick_ech_sni_value,
                                 &match,
                                 inner_stream_offset,
                                 inner_len,
                                 state->trick_ech_sni_shard1_delay_ms,
                                 state->trick_ech_sni_shard2_delay_ms);

    if (start_delay_out != NULL)
    {
        *start_delay_out = true;
    }
    return true;
}

static bool echsnitrickHandleHeldPair(tunnel_t *t, line_t *l, ipmanipulator_captured_packet_t *held_packet,
                                      sbuf_t *current_buf, const echsnitrick_tcp_packet_info_t *current_info,
                                      bool *block_flow_out, bool *start_delay_out)
{
    echsnitrick_tcp_packet_info_t held_info = {0};
    ipmanipulator_tstate_t       *state     = tunnelGetState(t);

    if (block_flow_out != NULL)
    {
        *block_flow_out = false;
    }

    if (start_delay_out != NULL)
    {
        *start_delay_out = false;
    }

    if (held_packet == NULL || held_packet->buf == NULL || held_packet->line == NULL || current_buf == NULL ||
        current_info == NULL)
    {
        if (held_packet != NULL)
        {
            echsnitrickRecycleCapturedPacket(held_packet);
        }

        if (current_buf != NULL)
        {
            echsnitrickSendNormalNow(t, l, current_buf);
        }

        return true;
    }

    if (! echsnitrickParseTcpPacketInfo(
            (const uint8_t *) sbufGetRawPtr(held_packet->buf), sbufGetLength(held_packet->buf), &held_info))
    {
        echsnitrickRecycleCapturedPacket(held_packet);
        echsnitrickSendNormalNow(t, l, current_buf);
        return true;
    }

    echsnitrickLogPairCapture(&held_info, current_info);

    if ((uint32_t) current_info->seq != held_info.seq + (uint32_t) held_info.tcp_payload_len ||
        held_info.tcp_payload_len == 0 || current_info->tcp_payload_len == 0)
    {
        if (echsnitrickIsHeldPayloadRetransmit(&held_info, current_info))
        {
            echsnitrickLogRetransmitStandaloneAttempt(&held_info);
            return echsnitrickHandleHeldStandalone(
                t, l, held_packet, current_buf, &held_info, block_flow_out, start_delay_out);
        }

        echsnitrickLogSequenceMismatchPassthrough(held_info.seq + (uint32_t) held_info.tcp_payload_len,
                                                  current_info->seq);
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *combined_packet = echsnitrickBuildCombinedPacket(held_packet->line, held_packet, &held_info, current_info);
    if (combined_packet == NULL)
    {
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    echsnitrick_clienthello_match_t        match        = {0};
    echsnitrick_clienthello_parse_status_e parse_status = echsnitrickParseClientHello(
        (const uint8_t *) sbufGetRawPtr(combined_packet), sbufGetLength(combined_packet), &match);

    if (parse_status == kEchSniClientHelloParseMiss)
    {
        echsnitrickLogParseMissPassthrough((uint32_t) held_info.tcp_payload_len +
                                           (uint32_t) current_info->tcp_payload_len);
        sbufDestroy(combined_packet);
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    if (parse_status == kEchSniClientHelloParseMalformed)
    {
        echsnitrickLogMalformedReject();

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    if (parse_status == kEchSniClientHelloParseNoSni)
    {
        echsnitrickLogMissingSniReject();

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    char           sni_name[256];
    const uint8_t *combined_packet_bytes = (const uint8_t *) sbufGetRawPtr(combined_packet);
    echsnitrickCopySniName(combined_packet_bytes, &match, sni_name, sizeof(sni_name));

    if (! match.has_ech)
    {
        echsnitrickLogMissingEchReject(sni_name);

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    uint32_t inner_offset = 0;
    uint32_t inner_len    = 0;
    if (! echsnitrickFindInnerClientHello(
            combined_packet_bytes, sbufGetLength(combined_packet), &match, &inner_offset, &inner_len))
    {
        echsnitrickLogMissingInnerReject(sni_name);

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    echsnitrickLogCandidateMatch(sni_name, &match, inner_offset, inner_len);

    uint32_t total_payload_len   = (uint32_t) held_info.tcp_payload_len + (uint32_t) current_info->tcp_payload_len;
    uint32_t inner_stream_offset = inner_offset - match.headers_len;

    if (inner_offset < match.headers_len || inner_stream_offset >= total_payload_len ||
        inner_len > total_payload_len - inner_stream_offset)
    {
        echsnitrickLogMalformedReject();

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    const uint8_t *combined_payload   = ((const uint8_t *) sbufGetRawPtr(combined_packet)) + held_info.headers_len;
    sbuf_t        *inner_template_buf = NULL;
    const echsnitrick_tcp_packet_info_t *inner_template_info = NULL;
    echsnitrickSelectTemplateForOffset(held_packet,
                                       &held_info,
                                       current_buf,
                                       current_info,
                                       inner_stream_offset,
                                       &inner_template_buf,
                                       &inner_template_info);

    if (inner_template_buf == NULL || inner_template_info == NULL)
    {
        sbufDestroy(combined_packet);
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    uint32_t packet_len = (uint32_t) inner_template_info->headers_len + inner_len;
    if (packet_len > GLOBAL_MTU_SIZE)
    {
        echsnitrickLogInnerMtuReject(sni_name, inner_len, packet_len);

        if (block_flow_out != NULL)
        {
            *block_flow_out = true;
        }

        sbufDestroy(combined_packet);
        echsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    uint8_t inner_flags  = echsnitrickGetContinuationPushFlags(inner_template_info->tcp_flags);
    sbuf_t *inner_packet = echsnitrickBuildPacketFromTemplate(held_packet->line,
                                                              inner_template_buf,
                                                              inner_template_info,
                                                              combined_payload + inner_stream_offset,
                                                              inner_len,
                                                              held_info.seq + inner_stream_offset,
                                                              inner_template_info->ip_identification,
                                                              inner_flags);

    if (inner_packet == NULL)
    {
        sbufDestroy(combined_packet);
        echsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbufDestroy(combined_packet);
    echsnitrickSendInnerThenOriginalDelayed(t,
                                            l,
                                            inner_packet,
                                            held_packet,
                                            current_buf,
                                            state->trick_ech_sni_shard1_delay_ms,
                                            state->trick_ech_sni_shard2_delay_ms);
    echsnitrickLogCraftedSuccess(sni_name,
                                 state->trick_ech_sni_value,
                                 &match,
                                 inner_stream_offset,
                                 inner_len,
                                 state->trick_ech_sni_shard1_delay_ms,
                                 state->trick_ech_sni_shard2_delay_ms);

    if (start_delay_out != NULL)
    {
        *start_delay_out = true;
    }
    return true;
}

void echsnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->echsni_flows == NULL)
    {
        return;
    }

    mutexLock(&state->echsni_flows_mutex);

    for (uint32_t i = 0; i < state->echsni_flows_capacity; ++i)
    {
        echsnitrickDestroyFlow(&state->echsni_flows[i]);
    }

    mutexUnlock(&state->echsni_flows_mutex);
    mutexDestroy(&state->echsni_flows_mutex);

    memoryFree(state->echsni_flows);
    state->echsni_flows          = NULL;
    state->echsni_flows_capacity = 0;
}

bool echsnitrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard l;

    ipmanipulator_tstate_t       *state  = tunnelGetState(t);
    echsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                      now_ms = getTickMS();

    if (! echsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    mutexLock(&state->echsni_flows_mutex);
    echsnitrickCleanupIdleFlowsLocked(state, now_ms);

    ipmanipulator_echsni_flow_t *flow = echsnitrickFindReverseFlowLocked(state, &info);
    if (flow != NULL)
    {
        flow->last_activity_ms = now_ms;

        if (echsnitrickHasFinOrRst(&info))
        {
            echsnitrickDestroyFlow(flow);
        }
    }

    mutexUnlock(&state->echsni_flows_mutex);
    return false;
}

bool echsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t       *state  = tunnelGetState(t);
    echsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                      now_ms = getTickMS();

    if (! echsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_captured_packet_t held_packet    = {0};
    bool                            bypass_current = false;

    mutexLock(&state->echsni_flows_mutex);
    echsnitrickCleanupIdleFlowsLocked(state, now_ms);

    ipmanipulator_echsni_flow_t *flow = echsnitrickFindFlowLocked(state, &info);

    if (flow != NULL && echsnitrickIsPureSyn(&info))
    {
        echsnitrickInitializeFlow(flow, &info, now_ms);
    }

    if (flow == NULL)
    {
        if (! echsnitrickIsPureSyn(&info))
        {
            mutexUnlock(&state->echsni_flows_mutex);
            return false;
        }

        flow = echsnitrickCreateFlowLocked(state, &info, now_ms);
    }

    if (flow == NULL)
    {
        mutexUnlock(&state->echsni_flows_mutex);
        LOGW("IpManipulator: ech-sni-trick failed to allocate a flow record");
        return false;
    }

    flow->last_activity_ms = now_ms;

    if (flow->phase == kIpManipulatorEchSniFlowPhaseBlocked)
    {
        if (echsnitrickHasFinOrRst(&info))
        {
            echsnitrickDestroyFlow(flow);
        }

        mutexUnlock(&state->echsni_flows_mutex);
        lineReuseBuffer(l, buf);
        return true;
    }

    uint8_t delay_phase = echsnitrickGetActiveDelayPhase(flow, now_ms);
    if (delay_phase != 0)
    {
        mutexUnlock(&state->echsni_flows_mutex);
        echsnitrickLogDelayDiscard(&info, delay_phase);
        lineReuseBuffer(l, buf);
        return true;
    }

    if (echsnitrickHasFinOrRst(&info))
    {
        if (flow->phase == kIpManipulatorEchSniFlowPhaseHoldThird)
        {
            held_packet       = flow->held_packet;
            flow->held_packet = (ipmanipulator_captured_packet_t) {0};
            bypass_current    = true;
        }

        echsnitrickDestroyFlow(flow);
        mutexUnlock(&state->echsni_flows_mutex);

        if (! bypass_current)
        {
            return false;
        }

        echsnitrickSendHeldThenCurrentNormal(t, &held_packet, l, buf);
        return true;
    }

    switch (flow->phase)
    {
    case kIpManipulatorEchSniFlowPhaseWarmup:
        if (flow->warmup_packets_seen < kEchSniWarmupPackets)
        {
            flow->warmup_packets_seen += 1;
            mutexUnlock(&state->echsni_flows_mutex);

            echsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        if (info.tcp_payload_len == 0)
        {
            flow->phase = kIpManipulatorEchSniFlowPhasePassthrough;
            mutexUnlock(&state->echsni_flows_mutex);

            echsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        flow->phase       = kIpManipulatorEchSniFlowPhaseHoldThird;
        flow->held_packet = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
        mutexUnlock(&state->echsni_flows_mutex);
        LOGD("IpManipulator: ech-sni-trick captured the third upstream packet payload=%u seq=%u for delayed inspection",
             info.tcp_payload_len,
             info.seq);
        return true;

    case kIpManipulatorEchSniFlowPhasePassthrough:
        mutexUnlock(&state->echsni_flows_mutex);
        echsnitrickSendNormalNow(t, l, buf);
        return true;

    case kIpManipulatorEchSniFlowPhaseHoldThird: {
        bool block_flow  = false;
        bool start_delay = false;

        held_packet       = flow->held_packet;
        flow->held_packet = (ipmanipulator_captured_packet_t) {0};

        mutexUnlock(&state->echsni_flows_mutex);

        bool handled = echsnitrickHandleHeldPair(t, l, &held_packet, buf, &info, &block_flow, &start_delay);

        mutexLock(&state->echsni_flows_mutex);
        flow = echsnitrickFindFlowLocked(state, &info);
        if (flow != NULL)
        {
            flow->last_activity_ms = getTickMS();
            echsnitrickFinalizeFlowLocked(flow, block_flow, start_delay, now_ms, state);
        }
        mutexUnlock(&state->echsni_flows_mutex);

        return handled;
    }

    case kIpManipulatorEchSniFlowPhaseBlocked:
    default:
        mutexUnlock(&state->echsni_flows_mutex);
        break;
    }

    return false;
}
