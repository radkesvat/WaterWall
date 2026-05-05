#include "trick.h"

#include "loggers/network_logger.h"

enum
{
    kSmuggleFinInitialQueueCapacity = 8,
    kSmuggleFinInitialFlows         = 32,
    kSmuggleFinIdleTimeoutMs        = 20U * 60U * 1000U
};

typedef struct smugglefintrick_tcp_packet_info_s
{
    uint32_t seq;
    uint32_t ack;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t ip_total_len;
    uint16_t ip_header_len;
    uint16_t tcp_header_len;
    uint16_t headers_len;
    uint16_t tcp_payload_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;
} smugglefintrick_tcp_packet_info_t;

static bool smugglefintrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                              smugglefintrick_tcp_packet_info_t *info)
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

    *info = (smugglefintrick_tcp_packet_info_t) {
        .seq             = lwip_ntohl(tcp_header->seqno),
        .ack             = lwip_ntohl(tcp_header->ackno),
        .src_addr        = ipheader->src.addr,
        .dst_addr        = ipheader->dest.addr,
        .ip_total_len    = ip_total_len,
        .ip_header_len   = ip_header_len,
        .tcp_header_len  = tcp_header_len,
        .headers_len     = headers_len,
        .tcp_payload_len = (uint16_t) (ip_total_len - headers_len),
        .src_port        = lwip_ntohs(tcp_header->src),
        .dst_port        = lwip_ntohs(tcp_header->dest),
        .tcp_flags       = TCPH_FLAGS(tcp_header),
    };

    return true;
}

static bool smugglefintrickShouldMirror(const smugglefintrick_tcp_packet_info_t *info)
{
    if (info == NULL)
    {
        return false;
    }

    if ((info->tcp_flags & TCP_ACK) == 0)
    {
        return false;
    }

    if ((info->tcp_flags & (TCP_SYN | TCP_FIN | TCP_RST)) != 0)
    {
        return false;
    }

    return info->tcp_payload_len > 0;
}

static uint32_t smugglefintrickAckAdvance(const smugglefintrick_tcp_packet_info_t *info)
{
    uint32_t advance = info->tcp_payload_len;

    if ((info->tcp_flags & TCP_SYN) != 0)
    {
        advance += 1U;
    }

    if ((info->tcp_flags & TCP_FIN) != 0)
    {
        advance += 1U;
    }

    return advance;
}

static bool smugglefintrickFlowMatches(const ipmanipulator_smuggle_fin_flow_t *flow,
                                       const smugglefintrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr &&
           flow->src_port == info->src_port && flow->dst_port == info->dst_port;
}

static bool smugglefintrickFlowMatchesReverse(const ipmanipulator_smuggle_fin_flow_t *flow,
                                              const smugglefintrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->dst_addr && flow->dst_addr == info->src_addr &&
           flow->src_port == info->dst_port && flow->dst_port == info->src_port;
}

static void smugglefintrickCleanupIdleFlowsLocked(ipmanipulator_tstate_t *state, uint64_t now_ms)
{
    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        ipmanipulator_smuggle_fin_flow_t *flow = &state->smuggle_fin_flows[i];

        if (! flow->active || ! flow->confirmed)
        {
            continue;
        }

        if (now_ms - flow->last_activity_ms < kSmuggleFinIdleTimeoutMs)
        {
            continue;
        }

        memoryZero(flow, sizeof(*flow));
    }
}

static ipmanipulator_smuggle_fin_flow_t *smugglefintrickFindFlowLocked(ipmanipulator_tstate_t *state,
                                                                       const smugglefintrick_tcp_packet_info_t *info)
{
    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        if (smugglefintrickFlowMatches(&state->smuggle_fin_flows[i], info))
        {
            return &state->smuggle_fin_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_smuggle_fin_flow_t *smugglefintrickFindReverseFlowLocked(ipmanipulator_tstate_t *state,
                                                                              const smugglefintrick_tcp_packet_info_t *info)
{
    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        if (smugglefintrickFlowMatchesReverse(&state->smuggle_fin_flows[i], info))
        {
            return &state->smuggle_fin_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_smuggle_fin_flow_t *smugglefintrickCreateFlowLocked(ipmanipulator_tstate_t *state,
                                                                         const smugglefintrick_tcp_packet_info_t *info,
                                                                         uint64_t now_ms)
{
    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        ipmanipulator_smuggle_fin_flow_t *flow = &state->smuggle_fin_flows[i];

        if (flow->active)
        {
            continue;
        }

        *flow = (ipmanipulator_smuggle_fin_flow_t) {
            .last_activity_ms = now_ms,
            .src_addr         = info->src_addr,
            .dst_addr         = info->dst_addr,
            .src_port         = info->src_port,
            .dst_port         = info->dst_port,
            .active           = true,
            .confirmed        = false,
        };
        return flow;
    }

    uint32_t old_capacity = state->smuggle_fin_flows_capacity;
    uint32_t new_capacity = max(kSmuggleFinInitialFlows, old_capacity * 2U);
    ipmanipulator_smuggle_fin_flow_t *grown =
        memoryReAllocate(state->smuggle_fin_flows, sizeof(*state->smuggle_fin_flows) * new_capacity);

    if (grown == NULL)
    {
        return NULL;
    }

    memoryZero(grown + old_capacity, sizeof(*grown) * (new_capacity - old_capacity));
    state->smuggle_fin_flows          = grown;
    state->smuggle_fin_flows_capacity = new_capacity;

    ipmanipulator_smuggle_fin_flow_t *flow = &state->smuggle_fin_flows[old_capacity];
    *flow = (ipmanipulator_smuggle_fin_flow_t) {
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .active           = true,
        .confirmed        = false,
    };
    return flow;
}

static bool smugglefintrickQueuePacketLocked(ipmanipulator_smuggle_fin_worker_state_t *worker_state, sbuf_t *buf,
                                             ipmanipulator_smuggle_fin_queue_direction_e direction)
{
    if (worker_state->queued_packets_count >= worker_state->queued_packets_capacity)
    {
        uint32_t new_capacity = max(kSmuggleFinInitialQueueCapacity, worker_state->queued_packets_capacity * 2U);
        ipmanipulator_smuggle_fin_queued_packet_t *grown =
            memoryReAllocate(worker_state->queued_packets, sizeof(*worker_state->queued_packets) * new_capacity);

        if (grown == NULL)
        {
            return false;
        }

        worker_state->queued_packets          = grown;
        worker_state->queued_packets_capacity = new_capacity;
    }

    worker_state->queued_packets[worker_state->queued_packets_count++] =
        (ipmanipulator_smuggle_fin_queued_packet_t) {.buf = buf, .direction = direction};
    return true;
}

static bool smugglefintrickQueuePacketOrDieLocked(ipmanipulator_smuggle_fin_worker_state_t *worker_state, sbuf_t *buf,
                                                  ipmanipulator_smuggle_fin_queue_direction_e direction)
{
    if (smugglefintrickQueuePacketLocked(worker_state, buf, direction))
    {
        return true;
    }

    LOGF("IpManipulator: smuggle-fin failed to grow the paused packet queue");
    terminateProgram(1);
    return false;
}

static bool smugglefintrickExpectedFinMatches(const ipmanipulator_smuggle_fin_worker_state_t *worker_state,
                                              const smugglefintrick_tcp_packet_info_t *info)
{
    return worker_state->paused && info != NULL && info->tcp_payload_len == 0 &&
           info->tcp_flags == (TCP_FIN | TCP_ACK) && info->src_addr == worker_state->expected_src_addr &&
           info->dst_addr == worker_state->expected_dst_addr && info->src_port == worker_state->expected_src_port &&
           info->dst_port == worker_state->expected_dst_port && info->seq == worker_state->expected_seq &&
           info->ack == worker_state->expected_ack;
}

static sbuf_t *smugglefintrickBuildMirrorFinPacket(line_t *l, sbuf_t *source_buf,
                                                   const smugglefintrick_tcp_packet_info_t *info)
{
    sbuf_t *clone = clonePacketWithLength(l, source_buf, info->headers_len);
    if (clone == NULL)
    {
        return NULL;
    }

    sbufSetLength(clone, info->headers_len);
    memoryCopyLarge(sbufGetMutablePtr(clone), sbufGetRawPtr(source_buf), info->headers_len);

    uint8_t        *packet     = sbufGetMutablePtr(clone);
    struct ip_hdr  *ipheader   = (struct ip_hdr *) packet;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + info->ip_header_len);

    uint32_t src_addr = ipheader->src.addr;
    ipheader->src.addr  = ipheader->dest.addr;
    ipheader->dest.addr = src_addr;

    uint16_t src_port = tcp_header->src;
    tcp_header->src  = tcp_header->dest;
    tcp_header->dest = src_port;

    IPH_LEN_SET(ipheader, lwip_htons(info->headers_len));
    tcp_header->seqno = lwip_htonl(info->ack);
    tcp_header->ackno = lwip_htonl(info->seq + smugglefintrickAckAdvance(info));
    TCPH_FLAGS_SET(tcp_header, TCP_FIN | TCP_ACK);

    return clone;
}

static void smugglefintrickFlushQueuedPackets(tunnel_t *t, line_t *l,
                                              ipmanipulator_smuggle_fin_queued_packet_t *queued_packets,
                                              uint32_t queued_packets_count)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    wid_t                   wid    = lineGetWID(l);

    for (uint32_t i = 0; i < queued_packets_count; ++i)
    {
        ipmanipulator_smuggle_fin_queued_packet_t *entry = &queued_packets[i];

        if (entry->direction == kIpManipulatorSmuggleFinQueueDirectionUpstream)
        {
            ipmanipulatorUpStreamPayload(t, l, entry->buf);
        }
        else
        {
            ipmanipulatorDownStreamPayload(t, l, entry->buf);
        }

        if (! lineIsAlive(l))
        {
            LOGF("IpManipulator: worker packet line died while replaying smuggle-fin queued packets");
            terminateProgram(1);
        }

        mutexLock(&state->smuggle_fin_mutex);
        bool paused_again = (wid < state->smuggle_fin_worker_states_count) && state->smuggle_fin_worker_states[wid].paused;

        if (paused_again)
        {
            ipmanipulator_smuggle_fin_worker_state_t *worker_state = &state->smuggle_fin_worker_states[wid];

            for (uint32_t remain = i + 1; remain < queued_packets_count; ++remain)
            {
                smugglefintrickQueuePacketOrDieLocked(worker_state, queued_packets[remain].buf,
                                                      queued_packets[remain].direction);
                queued_packets[remain].buf = NULL;
            }

            mutexUnlock(&state->smuggle_fin_mutex);
            break;
        }

        mutexUnlock(&state->smuggle_fin_mutex);
    }

    memoryFree(queued_packets);
}

static void smugglefintrickReleaseQueuedPacketsNow(tunnel_t *t, line_t *l)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    wid_t                   wid   = lineGetWID(l);
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets       = NULL;
    uint32_t                                   queued_packets_count = 0;

    if (wid >= state->smuggle_fin_worker_states_count)
    {
        return;
    }

    mutexLock(&state->smuggle_fin_mutex);

    ipmanipulator_smuggle_fin_worker_state_t *worker_state = &state->smuggle_fin_worker_states[wid];

    if (! worker_state->paused || ! worker_state->release_pending)
    {
        mutexUnlock(&state->smuggle_fin_mutex);
        return;
    }

    queued_packets       = worker_state->queued_packets;
    queued_packets_count = worker_state->queued_packets_count;

    memoryZero(worker_state, sizeof(*worker_state));

    mutexUnlock(&state->smuggle_fin_mutex);

    if (queued_packets != NULL && queued_packets_count > 0)
    {
        smugglefintrickFlushQueuedPackets(t, l, queued_packets, queued_packets_count);
    }
    else
    {
        memoryFree(queued_packets);
    }
}

static void smugglefintrickRunDelayedRelease(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t *t = arg1;
    line_t   *l = arg2;

    if (lineIsAlive(l))
    {
        smugglefintrickReleaseQueuedPacketsNow(t, l);
    }

    lineUnlock(l);
}

static void smugglefintrickScheduleQueuedRelease(tunnel_t *t, line_t *l, uint32_t delay_ms)
{
    if (delay_ms == 0 && getWID() == lineGetWID(l))
    {
        smugglefintrickReleaseQueuedPacketsNow(t, l);
        return;
    }

    lineLock(l);
    sendWorkerMessageTimed(lineGetWID(l), (WorkerMessageCalback) smugglefintrickRunDelayedRelease, delay_ms, t, l,
                           NULL);
}

bool smugglefintrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t            *state = tunnelGetState(t);
    smugglefintrick_tcp_packet_info_t  info  = {0};
    uint64_t                           now_ms = getTickMS();
    wid_t                              wid    = lineGetWID(l);

    if (state->trick_real_fin_upstream_tunnel == NULL || wid >= state->smuggle_fin_worker_states_count)
    {
        return false;
    }

    mutexLock(&state->smuggle_fin_mutex);
    smugglefintrickCleanupIdleFlowsLocked(state, now_ms);

    ipmanipulator_smuggle_fin_worker_state_t *worker_state = &state->smuggle_fin_worker_states[wid];

    if (worker_state->paused)
    {
        smugglefintrickQueuePacketOrDieLocked(worker_state, buf, kIpManipulatorSmuggleFinQueueDirectionUpstream);
        mutexUnlock(&state->smuggle_fin_mutex);
        return true;
    }

    mutexUnlock(&state->smuggle_fin_mutex);

    if (! smugglefintrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    mutexLock(&state->smuggle_fin_mutex);
    smugglefintrickCleanupIdleFlowsLocked(state, now_ms);
    worker_state = &state->smuggle_fin_worker_states[wid];

    ipmanipulator_smuggle_fin_flow_t *flow = smugglefintrickFindFlowLocked(state, &info);
    if (flow != NULL)
    {
        flow->last_activity_ms = now_ms;

        if (flow->confirmed)
        {
            mutexUnlock(&state->smuggle_fin_mutex);
            return false;
        }
    }

    if (worker_state->paused || ! smugglefintrickShouldMirror(&info))
    {
        mutexUnlock(&state->smuggle_fin_mutex);
        return false;
    }

    sbuf_t *fin_packet = smugglefintrickBuildMirrorFinPacket(l, buf, &info);
    if (fin_packet == NULL)
    {
        mutexUnlock(&state->smuggle_fin_mutex);
        return false;
    }

    if (flow == NULL)
    {
        flow = smugglefintrickCreateFlowLocked(state, &info, now_ms);
    }

    if (flow == NULL)
    {
        mutexUnlock(&state->smuggle_fin_mutex);
        lineReuseBuffer(l, fin_packet);
        LOGW("IpManipulator: smuggle-fin failed to allocate a connection record");
        return false;
    }

    flow->last_activity_ms        = now_ms;
    worker_state->flow_src_addr   = info.src_addr;
    worker_state->flow_dst_addr   = info.dst_addr;
    worker_state->flow_src_port   = info.src_port;
    worker_state->flow_dst_port   = info.dst_port;
    worker_state->expected_src_addr = info.dst_addr;
    worker_state->expected_dst_addr = info.src_addr;
    worker_state->expected_src_port = info.dst_port;
    worker_state->expected_dst_port = info.src_port;
    worker_state->expected_seq      = info.ack;
    worker_state->expected_ack      = info.seq + smugglefintrickAckAdvance(&info);
    worker_state->paused            = true;
    smugglefintrickQueuePacketOrDieLocked(worker_state, buf, kIpManipulatorSmuggleFinQueueDirectionUpstream);

    mutexUnlock(&state->smuggle_fin_mutex);

    bool original_recalculate_checksum = lineGetRecalculateChecksum(l);

    lineLock(l);
    lineSetRecalculateChecksum(l, true);
    tunnelUpStreamPayload(state->trick_real_fin_upstream_tunnel, l, fin_packet);

    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        LOGF("IpManipulator: worker packet line died during smuggle-fin send");
        terminateProgram(1);
    }

    lineSetRecalculateChecksum(l, original_recalculate_checksum);
    lineUnlock(l);

    LOGD("IpManipulator: smuggle-fin sent a mirrored FIN packet to \"%s\" and paused worker %u",
         state->trick_real_fin_upstream_node != NULL ? state->trick_real_fin_upstream_node->name : "(null)",
         (unsigned int) wid);

    return true;
}

bool smugglefintrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t            *state = tunnelGetState(t);
    smugglefintrick_tcp_packet_info_t  info  = {0};
    uint64_t                           now_ms = getTickMS();
    wid_t                              wid    = lineGetWID(l);
    bool                               parsed = smugglefintrickParseTcpPacketInfo(
        (const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info);

    if (wid >= state->smuggle_fin_worker_states_count)
    {
        return false;
    }

    mutexLock(&state->smuggle_fin_mutex);
    smugglefintrickCleanupIdleFlowsLocked(state, now_ms);

    if (parsed)
    {
        ipmanipulator_smuggle_fin_flow_t *reverse_flow = smugglefintrickFindReverseFlowLocked(state, &info);
        if (reverse_flow != NULL)
        {
            reverse_flow->last_activity_ms = now_ms;
        }
    }

    ipmanipulator_smuggle_fin_worker_state_t *worker_state = &state->smuggle_fin_worker_states[wid];

    if (! worker_state->paused)
    {
        mutexUnlock(&state->smuggle_fin_mutex);
        return false;
    }

    if (! smugglefintrickExpectedFinMatches(worker_state, parsed ? &info : NULL))
    {
        smugglefintrickQueuePacketOrDieLocked(worker_state, buf, kIpManipulatorSmuggleFinQueueDirectionDownstream);
        mutexUnlock(&state->smuggle_fin_mutex);
        return true;
    }

    if (worker_state->release_pending)
    {
        mutexUnlock(&state->smuggle_fin_mutex);
        lineReuseBuffer(l, buf);
        return true;
    }

    ipmanipulator_smuggle_fin_flow_t flow_key = {
        .src_addr = worker_state->flow_src_addr,
        .dst_addr = worker_state->flow_dst_addr,
        .src_port = worker_state->flow_src_port,
        .dst_port = worker_state->flow_dst_port,
    };

    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        ipmanipulator_smuggle_fin_flow_t *flow = &state->smuggle_fin_flows[i];

        if (! flow->active || flow->src_addr != flow_key.src_addr || flow->dst_addr != flow_key.dst_addr ||
            flow->src_port != flow_key.src_port || flow->dst_port != flow_key.dst_port)
        {
            continue;
        }

        flow->confirmed        = true;
        flow->last_activity_ms = now_ms;
        break;
    }

    worker_state->release_pending = true;
    uint32_t release_delay_ms = state->trick_smuggle_fin_delay_ms;

    mutexUnlock(&state->smuggle_fin_mutex);

    lineReuseBuffer(l, buf);

    if (release_delay_ms > 0)
    {
        LOGD("IpManipulator: successfully received the expected fin on worker %u and will release queued packets "
             "after %u ms",
             (unsigned int) wid,
             release_delay_ms);
    }
    else
    {
        LOGD("IpManipulator: successfully received the expected fin on worker %u", (unsigned int) wid);
    }

    smugglefintrickScheduleQueuedRelease(t, l, release_delay_ms);

    return true;
}

void smugglefintrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->smuggle_fin_worker_states == NULL)
    {
        return;
    }

    mutexLock(&state->smuggle_fin_mutex);

    for (uint32_t wi = 0; wi < state->smuggle_fin_worker_states_count; ++wi)
    {
        ipmanipulator_smuggle_fin_worker_state_t *worker_state = &state->smuggle_fin_worker_states[wi];

        for (uint32_t qi = 0; qi < worker_state->queued_packets_count; ++qi)
        {
            if (worker_state->queued_packets[qi].buf != NULL)
            {
                sbufDestroy(worker_state->queued_packets[qi].buf);
            }
        }

        memoryFree(worker_state->queued_packets);
        worker_state->queued_packets          = NULL;
        worker_state->queued_packets_count    = 0;
        worker_state->queued_packets_capacity = 0;
    }

    mutexUnlock(&state->smuggle_fin_mutex);
    mutexDestroy(&state->smuggle_fin_mutex);

    memoryFree(state->smuggle_fin_flows);
    memoryFree(state->smuggle_fin_worker_states);
    state->smuggle_fin_flows              = NULL;
    state->smuggle_fin_flows_capacity     = 0;
    state->smuggle_fin_worker_states      = NULL;
    state->smuggle_fin_worker_states_count = 0;
}
