#include "trick.h"

#include "loggers/network_logger.h"

enum
{
    kFirstSniIdleTimeoutMs = 20U * 60U * 1000U
};

typedef struct firstsnitrick_tcp_packet_info_s
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t seq;
    uint16_t ip_total_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t tcp_payload_len;
    uint8_t  tcp_flags;
    uint8_t  ttl;
} firstsnitrick_tcp_packet_info_t;

static void firstsnitrickResetFlow(ipmanipulator_firstsni_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    memoryZero(flow, sizeof(*flow));
}

static void firstsnitrickInitializeFlow(ipmanipulator_firstsni_flow_t *flow, const firstsnitrick_tcp_packet_info_t *info,
                                        uint64_t now_ms)
{
    if (flow == NULL || info == NULL)
    {
        return;
    }

    *flow = (ipmanipulator_firstsni_flow_t) {
        .created_ms           = now_ms,
        .last_activity_ms     = now_ms,
        .delay_window_until_ms = 0,
        .src_addr             = info->src_addr,
        .dst_addr             = info->dst_addr,
        .src_port             = info->src_port,
        .dst_port             = info->dst_port,
        .active               = true,
    };
}

static void firstsnitrickDestroyFlow(ipmanipulator_firstsni_flow_t *flow)
{
    firstsnitrickResetFlow(flow);
}

static bool firstsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                            firstsnitrick_tcp_packet_info_t *info)
{
    if (packet == NULL || info == NULL || packet_length < sizeof(struct ip_hdr))
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

    const struct tcp_hdr *tcp_header = (const struct tcp_hdr *) (packet + ip_header_len);
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

    *info = (firstsnitrick_tcp_packet_info_t) {
        .src_addr        = ipheader->src.addr,
        .dst_addr        = ipheader->dest.addr,
        .seq             = lwip_ntohl(tcp_header->seqno),
        .ip_total_len    = ip_total_len,
        .src_port        = lwip_ntohs(tcp_header->src),
        .dst_port        = lwip_ntohs(tcp_header->dest),
        .tcp_payload_len = (uint16_t) (ip_total_len - headers_len),
        .tcp_flags       = TCPH_FLAGS(tcp_header),
        .ttl             = ipheader->_ttl,
    };

    return true;
}

static bool firstsnitrickIsPureSyn(const firstsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && info->tcp_payload_len == 0 && info->tcp_flags == TCP_SYN;
}

static bool firstsnitrickHasFinOrRst(const firstsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static bool firstsnitrickFlowMatches(const ipmanipulator_firstsni_flow_t *flow, const firstsnitrick_tcp_packet_info_t *info)
{
    return flow != NULL && info != NULL && flow->active && flow->src_addr == info->src_addr &&
           flow->dst_addr == info->dst_addr && flow->src_port == info->src_port && flow->dst_port == info->dst_port;
}

static void firstsnitrickCleanupIdleFlowsLocked(ipmanipulator_tstate_t *state, uint64_t now_ms)
{
    if (state == NULL || state->first_sni_flows == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < state->first_sni_flows_capacity; ++i)
    {
        ipmanipulator_firstsni_flow_t *flow = &state->first_sni_flows[i];

        if (! flow->active)
        {
            continue;
        }

        if (now_ms - flow->last_activity_ms < kFirstSniIdleTimeoutMs)
        {
            continue;
        }

        firstsnitrickDestroyFlow(flow);
    }
}

static ipmanipulator_firstsni_flow_t *firstsnitrickFindFlowLocked(ipmanipulator_tstate_t *state,
                                                                  const firstsnitrick_tcp_packet_info_t *info)
{
    if (state == NULL || state->first_sni_flows == NULL)
    {
        return NULL;
    }

    for (uint32_t i = 0; i < state->first_sni_flows_capacity; ++i)
    {
        if (firstsnitrickFlowMatches(&state->first_sni_flows[i], info))
        {
            return &state->first_sni_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_firstsni_flow_t *firstsnitrickCreateFlowLocked(ipmanipulator_tstate_t *state,
                                                                    const firstsnitrick_tcp_packet_info_t *info,
                                                                    uint64_t now_ms)
{
    if (state == NULL || info == NULL)
    {
        return NULL;
    }

    for (uint32_t i = 0; i < state->first_sni_flows_capacity; ++i)
    {
        ipmanipulator_firstsni_flow_t *flow = &state->first_sni_flows[i];

        if (flow->active)
        {
            continue;
        }

        firstsnitrickInitializeFlow(flow, info, now_ms);
        return flow;
    }

    uint32_t old_capacity = state->first_sni_flows_capacity;
    uint32_t new_capacity = max(kIpManipulatorSmuggleInitialFlows, old_capacity * 2U);
    ipmanipulator_firstsni_flow_t *grown =
        memoryReAllocate(state->first_sni_flows, sizeof(*state->first_sni_flows) * new_capacity);

    if (grown == NULL)
    {
        return NULL;
    }

    memoryZero(grown + old_capacity, sizeof(*grown) * (new_capacity - old_capacity));
    state->first_sni_flows          = grown;
    state->first_sni_flows_capacity = new_capacity;

    ipmanipulator_firstsni_flow_t *flow = &state->first_sni_flows[old_capacity];
    firstsnitrickInitializeFlow(flow, info, now_ms);
    return flow;
}

static uint32_t firstsnitrickGetTailDelayMs(const ipmanipulator_tstate_t *state)
{
    if (state == NULL)
    {
        return 0;
    }

    uint64_t replay_span_ms = 0;
    if (state->trick_first_sni_count > 1 && state->trick_first_sni_replay_delay_ms > 0)
    {
        replay_span_ms =
            (uint64_t) (state->trick_first_sni_count - 1U) * (uint64_t) state->trick_first_sni_replay_delay_ms;
    }

    return (uint32_t) (replay_span_ms + (uint64_t) state->trick_first_sni_final_delay_ms);
}

static void firstsnitrickArmDelayWindow(tunnel_t *t, sbuf_t *buf, uint64_t now_ms)
{
    ipmanipulator_tstate_t     *state         = tunnelGetState(t);
    firstsnitrick_tcp_packet_info_t info          = {0};
    uint32_t                    tail_delay_ms = firstsnitrickGetTailDelayMs(state);

    if (tail_delay_ms == 0 || state->first_sni_flows == NULL || buf == NULL)
    {
        return;
    }

    if (! firstsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return;
    }

    mutexLock(&state->first_sni_flows_mutex);
    firstsnitrickCleanupIdleFlowsLocked(state, now_ms);

    ipmanipulator_firstsni_flow_t *flow = firstsnitrickFindFlowLocked(state, &info);
    if (flow == NULL)
    {
        flow = firstsnitrickCreateFlowLocked(state, &info, now_ms);
    }

    if (flow != NULL)
    {
        flow->last_activity_ms      = now_ms;
        flow->delay_window_until_ms = now_ms + tail_delay_ms;
    }

    mutexUnlock(&state->first_sni_flows_mutex);

    if (flow == NULL)
    {
        LOGW("IpManipulator: first-sni failed to allocate a flow record for delayed replay handling");
    }
}

static bool setTcpSequenceRandom(uint8_t *packet, uint32_t packet_length)
{
    if (packet_length < sizeof(struct ip_hdr))
    {
        return false;
    }

    struct ip_hdr *iph = (struct ip_hdr *) packet;
    if (IPH_V(iph) != 4 || IPH_PROTO(iph) != IPPROTO_TCP)
    {
        return false;
    }

    uint8_t ip_hlen = IPH_HL_BYTES(iph);
    if (ip_hlen < sizeof(struct ip_hdr) || packet_length < ip_hlen + sizeof(struct tcp_hdr))
    {
        return false;
    }

    struct tcp_hdr *tcph = (struct tcp_hdr *) (packet + ip_hlen);
    uint8_t         tcp_hlen = TCPH_HDRLEN_BYTES(tcph);
    if (tcp_hlen < sizeof(struct tcp_hdr) || packet_length < ip_hlen + tcp_hlen)
    {
        return false;
    }

    tcph->seqno = lwip_htonl(fastRand32());
    return true;
}

static sbuf_t *craftFirstSniPacket(tunnel_t *t, line_t *l, sbuf_t *buf, const sni_match_t *match)
{
    ipmanipulator_tstate_t *state  = tunnelGetState(t);
    const uint8_t          *source = (const uint8_t *) sbufGetRawPtr(buf);

    if (match->has_tls13_psk_binder &&
        ((match->sni_name_len != state->trick_first_sni_value_len) ||
         memcmp(source + match->sni_name_offset, state->trick_first_sni_value, match->sni_name_len) != 0))
    {
        LOGD("firstsnitrick: skipping TLS ClientHello rewrite because pre_shared_key binders are present");
        return NULL;
    }

    uint32_t original_packet_len  = match->ip_total_len;
    int32_t  delta                = (int32_t) state->trick_first_sni_value_len - (int32_t) match->sni_name_len;
    int32_t  new_ip_total_len     = (int32_t) match->ip_total_len + delta;
    int32_t  new_extensions_len   = (int32_t) match->extensions_len + delta;
    int32_t  new_server_name_list_len = (int32_t) match->server_name_list_len + delta;
    int32_t  new_server_name_ext_len  = (int32_t) match->server_name_ext_len + delta;
    int32_t  new_tls_record_len       = (int32_t) match->tls_record_len + delta;
    int64_t  new_client_hello_len     = (int64_t) match->client_hello_len + delta;

    if (delta > 0 && original_packet_len > UINT32_MAX - (uint32_t) delta)
    {
        LOGW("firstsnitrick: packet length overflow while expanding fake SNI");
        return NULL;
    }

    if (delta < 0 && original_packet_len < (uint32_t) (-delta))
    {
        return NULL;
    }

    if (delta > 0 && match->ip_total_len > UINT16_MAX - (uint16_t) delta)
    {
        LOGW("firstsnitrick: IPv4 total length overflow while expanding fake SNI");
        return NULL;
    }

    if (delta > 0 && match->server_name_list_len > UINT16_MAX - (uint16_t) delta)
    {
        LOGW("firstsnitrick: TLS server-name list length overflow while expanding fake SNI");
        return NULL;
    }

    if (delta > 0 && match->server_name_ext_len > UINT16_MAX - (uint16_t) delta)
    {
        LOGW("firstsnitrick: TLS server-name extension length overflow while expanding fake SNI");
        return NULL;
    }

    if (delta > 0 && match->extensions_len > UINT16_MAX - (uint16_t) delta)
    {
        LOGW("firstsnitrick: TLS extensions length overflow while expanding fake SNI");
        return NULL;
    }

    if (delta > 0 && match->tls_record_len > UINT16_MAX - (uint16_t) delta)
    {
        LOGW("firstsnitrick: TLS record length overflow while expanding fake SNI");
        return NULL;
    }

    if (delta > 0 && match->client_hello_len > 0xFFFFFFU - (uint32_t) delta)
    {
        LOGW("firstsnitrick: TLS ClientHello length overflow while expanding fake SNI");
        return NULL;
    }

    if (new_ip_total_len <= 0 || new_extensions_len <= 0 || new_server_name_list_len <= 0 ||
        new_server_name_ext_len <= 0 || new_tls_record_len <= 0 || new_client_hello_len <= 0)
    {
        LOGW("firstsnitrick: fake SNI would make packet lengths invalid");
        return NULL;
    }

    uint32_t new_len = original_packet_len + (uint32_t) delta;
    if (delta < 0)
    {
        new_len = original_packet_len - (uint32_t) (-delta);
    }

    sbuf_t *clone = clonePacketWithLength(l, buf, new_len);
    if (clone == NULL)
    {
        return NULL;
    }

    uint8_t  *dest        = sbufGetMutablePtr(clone);
    uint32_t  prefix_len  = match->sni_name_offset;
    uint32_t  tail_offset = match->sni_name_offset + match->sni_name_len;
    if (tail_offset > original_packet_len)
    {
        reuseBuffer(clone);
        return NULL;
    }
    uint32_t tail_len = original_packet_len - tail_offset;

    memoryCopyLarge(dest, source, prefix_len);
    memoryCopyLarge(dest + prefix_len, state->trick_first_sni_value, state->trick_first_sni_value_len);
    memoryCopyLarge(dest + prefix_len + state->trick_first_sni_value_len, source + tail_offset, tail_len);

    PUT_BE16(dest + match->sni_name_len_field_offset, state->trick_first_sni_value_len);
    PUT_BE16(dest + match->extensions_len_field_offset, (uint16_t) new_extensions_len);
    PUT_BE16(dest + match->server_name_list_len_field_offset, (uint16_t) new_server_name_list_len);
    PUT_BE16(dest + match->server_name_ext_len_field_offset, (uint16_t) new_server_name_ext_len);
    PUT_BE16(dest + match->tls_record_len_field_offset, (uint16_t) new_tls_record_len);
    PUT_BE24(dest + match->client_hello_len_field_offset, (uint32_t) new_client_hello_len);

    struct ip_hdr *ipheader = (struct ip_hdr *) dest;
    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) new_ip_total_len));

    LOGD("IpManipulator: first-sni crafted fake ClientHello original-sni=\"%.*s\" fake-sni=\"%.*s\" "
         "ip-len=%u->%u tls-record=%u->%u client-hello=%u->%u",
         (int) match->sni_name_len,
         (const char *) (source + match->sni_name_offset),
         (int) state->trick_first_sni_value_len,
         state->trick_first_sni_value,
         (unsigned int) match->ip_total_len,
         (unsigned int) (uint16_t) new_ip_total_len,
         (unsigned int) match->tls_record_len,
         (unsigned int) (uint16_t) new_tls_record_len,
         match->client_hello_len,
         (uint32_t) new_client_hello_len);

    return clone;
}

static void prepareFirstSniPacketForSend(tunnel_t *t, sbuf_t *packet)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->trick_first_sni_ttl >= 0)
    {
        struct ip_hdr *fake_ipheader = (struct ip_hdr *) sbufGetMutablePtr(packet);
        IPH_TTL_SET(fake_ipheader, (uint8_t) state->trick_first_sni_ttl);
    }

    if (state->trick_first_sni_random_tcp_sequence)
    {
        setTcpSequenceRandom(sbufGetMutablePtr(packet), sbufGetLength(packet));
    }
}

static void firstsnitrickSendCraftedPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    firstsnitrick_tcp_packet_info_t before = {0};
    discard firstsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &before);

    prepareFirstSniPacketForSend(t, buf);

    firstsnitrick_tcp_packet_info_t after = {0};
    if (firstsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &after))
    {
        ipmanipulator_tstate_t *state = tunnelGetState(t);

        LOGD("IpManipulator: first-sni sending crafted packet ip-len=%u payload=%u seq=%u ttl=%u %u:%u -> %u:%u",
             (unsigned int) after.ip_total_len,
             (unsigned int) after.tcp_payload_len,
             after.seq,
             (unsigned int) after.ttl,
             after.src_addr,
             (unsigned int) after.src_port,
             after.dst_addr,
             (unsigned int) after.dst_port);

        if (state->trick_first_sni_random_tcp_sequence && before.seq != after.seq)
        {
            LOGD("IpManipulator: first-sni randomized crafted TCP sequence %u -> %u", before.seq, after.seq);
        }
    }

    ipmanipulatorSendUpstreamMaybeSegmented(t, l, buf);
}

static void firstsnitrickSendOriginalPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    firstsnitrick_tcp_packet_info_t info = {0};
    if (firstsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        LOGD("IpManipulator: first-sni forwarding original packet ip-len=%u payload=%u seq=%u %u:%u -> %u:%u",
             (unsigned int) info.ip_total_len,
             (unsigned int) info.tcp_payload_len,
             info.seq,
             info.src_addr,
             (unsigned int) info.src_port,
             info.dst_addr,
             (unsigned int) info.dst_port);
    }

    /*
        Packet lines are shared worker state, so delayed sends cannot rely on the
        current recalculate_checksum scratch flag still belonging to this packet.
        Recomputing here is safe for the original packet and preserves correctness
        if earlier tricks in the same pass already changed it.
    */
    ipmanipulatorSendUpstreamMaybeSegmented(t, l, buf);
}

static bool firstsnitrickMaybeDelayFlowPacket(tunnel_t *t, line_t *l, sbuf_t *buf,
                                              const firstsnitrick_tcp_packet_info_t *info, uint64_t now_ms)
{
    ipmanipulator_tstate_t *state         = tunnelGetState(t);
    uint32_t                tail_delay_ms = firstsnitrickGetTailDelayMs(state);

    if (state->first_sni_flows == NULL || tail_delay_ms == 0 || info == NULL)
    {
        return false;
    }

    mutexLock(&state->first_sni_flows_mutex);
    firstsnitrickCleanupIdleFlowsLocked(state, now_ms);

    ipmanipulator_firstsni_flow_t *flow = firstsnitrickFindFlowLocked(state, info);

    if (flow != NULL && firstsnitrickIsPureSyn(info))
    {
        firstsnitrickInitializeFlow(flow, info, now_ms);
    }
    else if (flow == NULL && firstsnitrickIsPureSyn(info))
    {
        flow = firstsnitrickCreateFlowLocked(state, info, now_ms);
    }

    if (flow != NULL)
    {
        flow->last_activity_ms = now_ms;
    }

    bool delay_active = flow != NULL && now_ms < flow->delay_window_until_ms;
    if (! delay_active && flow != NULL && firstsnitrickHasFinOrRst(info))
    {
        firstsnitrickDestroyFlow(flow);
    }

    mutexUnlock(&state->first_sni_flows_mutex);

    if (! delay_active)
    {
        return false;
    }

    LOGD("IpManipulator: first-sni delaying flow packet payload=%u for %u ms while replay/final-delay window is active",
         (unsigned int) info->tcp_payload_len,
         tail_delay_ms);
    lineScheduleDelayedTaskWithBuf(l, firstsnitrickSendOriginalPacket, tail_delay_ms, t, buf);
    return true;
}

static void firstsnitrickSendLastCraftedThenOriginal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    sni_match_t             match = {0};

    if (parseClientHelloSni((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &match))
    {
        sbuf_t *fake_packet = craftFirstSniPacket(t, l, buf, &match);
        if (fake_packet != NULL)
        {
            firstsnitrickSendCraftedPacket(t, l, fake_packet);

            if (! lineIsAlive(l))
            {
                reuseBuffer(buf);
                return;
            }
        }
        else
        {
            LOGD("IpManipulator: first-sni could not craft the last replay packet; forwarding original ClientHello");
        }
    }

    if (state->trick_first_sni_final_delay_ms > 0)
    {
        lineScheduleDelayedTaskWithBuf(
            l, firstsnitrickSendOriginalPacket, state->trick_first_sni_final_delay_ms, t, buf);
        return;
    }

    firstsnitrickSendOriginalPacket(t, l, buf);
}

static bool firstsnitrickHandleClientHello(tunnel_t *t, line_t *l, sbuf_t *buf, uint64_t now_ms)
{
    ipmanipulator_tstate_t *state         = tunnelGetState(t);
    sni_match_t             match         = {0};
    uint32_t                tail_delay_ms = firstsnitrickGetTailDelayMs(state);

    if (! parseClientHelloSni((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &match))
    {
        return false;
    }

    sbuf_t *fake_packet = craftFirstSniPacket(t, l, buf, &match);
    if (fake_packet == NULL)
    {
        LOGD("IpManipulator: first-sni matched ClientHello but skipped fake packet crafting; forwarding original");
        firstsnitrickSendOriginalPacket(t, l, buf);
        return true;
    }

    LOGD("IpManipulator: first-sni injecting SNI \"%.*s\" %u time(s) before forwarding original ClientHello "
         "ip-len=%u tls-record=%u",
         (int) state->trick_first_sni_value_len,
         state->trick_first_sni_value,
         state->trick_first_sni_count,
         (unsigned int) match.ip_total_len,
         (unsigned int) match.tls_record_len);

    lineLock(l);

    firstsnitrickSendCraftedPacket(t, l, fake_packet);

    if (! lineIsAlive(l))
    {
        reuseBuffer(buf);
        lineUnlock(l);
        return true;
    }

    if (state->trick_first_sni_count == 1)
    {
        if (state->trick_first_sni_final_delay_ms > 0)
        {
            lineScheduleDelayedTaskWithBuf(
                l, firstsnitrickSendOriginalPacket, state->trick_first_sni_final_delay_ms, t, buf);
            if (tail_delay_ms > 0)
            {
                firstsnitrickArmDelayWindow(t, buf, now_ms);
            }
            lineUnlock(l);
            return true;
        }

        firstsnitrickSendOriginalPacket(t, l, buf);
        lineUnlock(l);
        return true;
    }

    if (state->trick_first_sni_replay_delay_ms == 0)
    {
        for (uint32_t replay_index = 1; replay_index < state->trick_first_sni_count; ++replay_index)
        {
            sbuf_t *extra_packet = craftFirstSniPacket(t, l, buf, &match);
            if (extra_packet == NULL)
            {
                break;
            }

            firstsnitrickSendCraftedPacket(t, l, extra_packet);
            if (! lineIsAlive(l))
            {
                reuseBuffer(buf);
                lineUnlock(l);
                return true;
            }
        }

        if (state->trick_first_sni_final_delay_ms > 0)
        {
            lineScheduleDelayedTaskWithBuf(
                l, firstsnitrickSendOriginalPacket, state->trick_first_sni_final_delay_ms, t, buf);
            if (tail_delay_ms > 0)
            {
                firstsnitrickArmDelayWindow(t, buf, now_ms);
            }
            lineUnlock(l);
            return true;
        }

        firstsnitrickSendOriginalPacket(t, l, buf);
        lineUnlock(l);
        return true;
    }

    for (uint32_t replay_index = 1; replay_index + 1 < state->trick_first_sni_count; ++replay_index)
    {
        sbuf_t *scheduled_packet = craftFirstSniPacket(t, l, buf, &match);
        if (scheduled_packet == NULL)
        {
            break;
        }

        uint32_t delay_ms = replay_index * state->trick_first_sni_replay_delay_ms;
        lineScheduleDelayedTaskWithBuf(l, firstsnitrickSendCraftedPacket, delay_ms, t, scheduled_packet);
    }

    lineScheduleDelayedTaskWithBuf(l,
                                   firstsnitrickSendLastCraftedThenOriginal,
                                   (state->trick_first_sni_count - 1) * state->trick_first_sni_replay_delay_ms,
                                   t,
                                   buf);
    if (tail_delay_ms > 0)
    {
        firstsnitrickArmDelayWindow(t, buf, now_ms);
    }

    lineUnlock(l);
    return true;
}

bool firstsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    firstsnitrick_tcp_packet_info_t  info       = {0};
    uint64_t                         now_ms     = getTickMS();

    if (firstsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info) &&
        firstsnitrickMaybeDelayFlowPacket(t, l, buf, &info, now_ms))
    {
        return true;
    }

    if (firstsnitrickHandleClientHello(t, l, buf, now_ms))
    {
        return true;
    }

    ipmanipulator_tls_capture_slot_t   captured_slot  = {0};
    ipmanipulator_tls_capture_status_e capture_status =
        ipmanipulatorCaptureTlsClientHello(t, l, buf, kIpManipulatorTlsCaptureKindFirstSni, &captured_slot);

    if (capture_status == kIpManipulatorTlsCaptureStatusPending ||
        capture_status == kIpManipulatorTlsCaptureStatusBypassed)
    {
        return true;
    }

    if (capture_status == kIpManipulatorTlsCaptureStatusReady)
    {
        sbuf_t *captured_packet = captured_slot.assembled_packet;
        captured_slot.assembled_packet = NULL;
        ipmanipulatorRecycleCapturedTlsPackets(t, &captured_slot);

        LOGD("IpManipulator: first-sni handling assembled fragmented ClientHello packet len=%u",
             sbufGetLength(captured_packet));

        if (! firstsnitrickHandleClientHello(t, l, captured_packet, now_ms))
        {
            LOGD("IpManipulator: first-sni assembled packet was not a usable ClientHello; forwarding it unchanged");
            firstsnitrickSendOriginalPacket(t, l, captured_packet);
        }

        return true;
    }

    return false;
}

void firstsnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->first_sni_flows == NULL)
    {
        return;
    }

    mutexLock(&state->first_sni_flows_mutex);

    for (uint32_t i = 0; i < state->first_sni_flows_capacity; ++i)
    {
        firstsnitrickDestroyFlow(&state->first_sni_flows[i]);
    }

    mutexUnlock(&state->first_sni_flows_mutex);
    mutexDestroy(&state->first_sni_flows_mutex);

    memoryFree(state->first_sni_flows);
    state->first_sni_flows          = NULL;
    state->first_sni_flows_capacity = 0;
}
