#include "trick.h"

#include "loggers/network_logger.h"

enum
{
    kSmuggleFinInitialQueueCapacity     = 8,
    kSmuggleFinMaxQueueCapacity         = 256,
    kSmuggleFinInitialFlows             = 32,
    kSmuggleFinUnconfirmedIdleTimeoutMs = 10U * 1000U,
    kSmuggleFinIdleTimeoutMs            = 20U * 60U * 1000U
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

typedef struct smugglefintrick_release_context_s
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t generation;
    uint16_t src_port;
    uint16_t dst_port;
    bool     force;
} smugglefintrick_release_context_t;

#ifdef IPMANIPULATOR_SMUGGLEFIN_TEST_HOOKS
void ipmanipulatorSmuggleFinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                              WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                              void *arg2, void *arg3);
#endif

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
    if (info == NULL || (info->tcp_flags & TCP_ACK) == 0)
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

static bool smugglefintrickFlowMatches(const ipmanipulator_smuggle_fin_flow_t  *flow,
                                       const smugglefintrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr &&
           flow->src_port == info->src_port && flow->dst_port == info->dst_port;
}

static bool smugglefintrickFlowMatchesReverse(const ipmanipulator_smuggle_fin_flow_t  *flow,
                                              const smugglefintrick_tcp_packet_info_t *info)
{
    return flow->active && flow->src_addr == info->dst_addr && flow->dst_addr == info->src_addr &&
           flow->src_port == info->dst_port && flow->dst_port == info->src_port;
}

static bool smugglefintrickFlowMatchesReleaseContext(const ipmanipulator_smuggle_fin_flow_t  *flow,
                                                     const smugglefintrick_release_context_t *context)
{
    return flow->active && flow->src_addr == context->src_addr && flow->dst_addr == context->dst_addr &&
           flow->src_port == context->src_port && flow->dst_port == context->dst_port;
}

static bool smugglefintrickExpectedFinMatches(const ipmanipulator_smuggle_fin_flow_t  *flow,
                                              const smugglefintrick_tcp_packet_info_t *info)
{
    return flow->active && flow->paused && info->tcp_payload_len == 0 && info->tcp_flags == (TCP_FIN | TCP_ACK) &&
           info->src_addr == flow->expected_src_addr && info->dst_addr == flow->expected_dst_addr &&
           info->src_port == flow->expected_src_port && info->dst_port == flow->expected_dst_port &&
           info->seq == flow->expected_seq && info->ack == flow->expected_ack;
}

static void smugglefintrickDestroyFlow(ipmanipulator_smuggle_fin_flow_t *flow)
{
    for (uint32_t i = 0; i < flow->queued_packets_count; ++i)
    {
        if (flow->queued_packets[i].buf != NULL)
        {
            sbufDestroy(flow->queued_packets[i].buf);
        }
    }

    memoryFree(flow->queued_packets);
    memoryZero(flow, sizeof(*flow));
}

static bool smugglefintrickCleanupIdleFlowLocked(ipmanipulator_smuggle_fin_flow_t *flow, uint64_t now_ms)
{
    if (! flow->active || flow->paused)
    {
        return false;
    }

    uint64_t timeout_ms = flow->confirmed ? kSmuggleFinIdleTimeoutMs : kSmuggleFinUnconfirmedIdleTimeoutMs;
    if (now_ms - flow->last_activity_ms < timeout_ms)
    {
        return false;
    }

    smugglefintrickDestroyFlow(flow);
    return true;
}

static ipmanipulator_smuggle_fin_flow_t *smugglefintrickInspectUpstreamFlowsLocked(
    ipmanipulator_tstate_t *state, const smugglefintrick_tcp_packet_info_t *info, uint64_t now_ms, wid_t wid,
    bool *worker_has_paused_flow)
{
    ipmanipulator_smuggle_fin_flow_t *matched_flow = NULL;
    *worker_has_paused_flow                        = false;

    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        ipmanipulator_smuggle_fin_flow_t *flow = &state->smuggle_fin_flows[i];

        if (smugglefintrickCleanupIdleFlowLocked(flow, now_ms))
        {
            continue;
        }

        if (matched_flow == NULL && smugglefintrickFlowMatches(flow, info))
        {
            matched_flow = flow;
        }

        *worker_has_paused_flow |= flow->active && flow->paused && flow->line != NULL && lineGetWID(flow->line) == wid;
    }

    return matched_flow;
}

static void smugglefintrickInspectDownstreamFlowsLocked(ipmanipulator_tstate_t                  *state,
                                                        const smugglefintrick_tcp_packet_info_t *info, uint64_t now_ms,
                                                        ipmanipulator_smuggle_fin_flow_t **expected_flow,
                                                        ipmanipulator_smuggle_fin_flow_t **reverse_flow)
{
    *expected_flow = NULL;
    *reverse_flow  = NULL;

    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        ipmanipulator_smuggle_fin_flow_t *flow = &state->smuggle_fin_flows[i];

        if (smugglefintrickCleanupIdleFlowLocked(flow, now_ms))
        {
            continue;
        }

        if (*expected_flow == NULL && smugglefintrickExpectedFinMatches(flow, info))
        {
            *expected_flow = flow;
        }

        if (*reverse_flow == NULL && smugglefintrickFlowMatchesReverse(flow, info))
        {
            *reverse_flow = flow;
        }
    }
}

static ipmanipulator_smuggle_fin_flow_t *smugglefintrickFindReleaseFlowLocked(
    ipmanipulator_tstate_t *state, const smugglefintrick_release_context_t *context)
{
    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        if (smugglefintrickFlowMatchesReleaseContext(&state->smuggle_fin_flows[i], context))
        {
            return &state->smuggle_fin_flows[i];
        }
    }

    return NULL;
}

static ipmanipulator_smuggle_fin_flow_t *smugglefintrickCreateFlowLocked(ipmanipulator_tstate_t                  *state,
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
        };
        return flow;
    }

    uint32_t                          old_capacity = state->smuggle_fin_flows_capacity;
    uint32_t                          new_capacity = max(kSmuggleFinInitialFlows, old_capacity * 2U);
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
    *flow                                  = (ipmanipulator_smuggle_fin_flow_t) {
                                         .last_activity_ms = now_ms,
                                         .src_addr         = info->src_addr,
                                         .dst_addr         = info->dst_addr,
                                         .src_port         = info->src_port,
                                         .dst_port         = info->dst_port,
                                         .active           = true,
    };
    return flow;
}

static bool smugglefintrickQueuePacketLocked(ipmanipulator_smuggle_fin_flow_t *flow, sbuf_t *buf,
                                             ipmanipulator_smuggle_fin_queue_direction_e direction)
{
    if (flow->queued_packets_count >= kSmuggleFinMaxQueueCapacity)
    {
        return false;
    }

    if (flow->queued_packets_count >= flow->queued_packets_capacity)
    {
        uint32_t new_capacity = max(kSmuggleFinInitialQueueCapacity, flow->queued_packets_capacity * 2U);
        new_capacity          = min(new_capacity, (uint32_t) kSmuggleFinMaxQueueCapacity);

        ipmanipulator_smuggle_fin_queued_packet_t *grown =
            memoryReAllocate(flow->queued_packets, sizeof(*flow->queued_packets) * new_capacity);

        if (grown == NULL)
        {
            return false;
        }

        flow->queued_packets          = grown;
        flow->queued_packets_capacity = new_capacity;
    }

    flow->queued_packets[flow->queued_packets_count++] =
        (ipmanipulator_smuggle_fin_queued_packet_t) {.buf = buf, .direction = direction};
    return true;
}

static void smugglefintrickDetachQueuedPacketsLocked(ipmanipulator_smuggle_fin_flow_t *flow, bool force,
                                                     uint64_t                                    now_ms,
                                                     ipmanipulator_smuggle_fin_queued_packet_t **queued_packets,
                                                     uint32_t                                   *queued_packets_count)
{
    *queued_packets       = flow->queued_packets;
    *queued_packets_count = flow->queued_packets_count;

    flow->queued_packets          = NULL;
    flow->queued_packets_count    = 0;
    flow->queued_packets_capacity = 0;
    flow->paused                  = false;
    flow->release_pending         = false;
    flow->paused_at_ms            = 0;
    flow->line                    = NULL;
    flow->last_activity_ms        = now_ms;
    if (force)
    {
        flow->confirmed = true;
    }
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

    uint32_t src_addr   = ipheader->src.addr;
    ipheader->src.addr  = ipheader->dest.addr;
    ipheader->dest.addr = src_addr;

    uint16_t src_port = tcp_header->src;
    tcp_header->src   = tcp_header->dest;
    tcp_header->dest  = src_port;

    IPH_LEN_SET(ipheader, lwip_htons(info->headers_len));
    tcp_header->seqno = lwip_htonl(info->ack);
    tcp_header->ackno = lwip_htonl(info->seq + smugglefintrickAckAdvance(info));
    TCPH_FLAGS_SET(tcp_header, TCP_FIN | TCP_ACK);

    return clone;
}

static void smugglefintrickForwardRealFin(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    tunnelUpStreamPayload(state->trick_real_fin_upstream_tunnel, l, buf);
}

static void smugglefintrickFlushQueuedPackets(tunnel_t *t, line_t *l,
                                              ipmanipulator_smuggle_fin_queued_packet_t *queued_packets,
                                              uint32_t                                   queued_packets_count)
{
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
            abortProgramNow(1);
        }
    }

    memoryFree(queued_packets);
}

static smugglefintrick_release_context_t *smugglefintrickCreateReleaseContextLocked(
    const ipmanipulator_smuggle_fin_flow_t *flow, bool force)
{
    smugglefintrick_release_context_t *context = memoryAllocate(sizeof(*context));
    *context                                   = (smugglefintrick_release_context_t) {
                                          .src_addr   = flow->src_addr,
                                          .dst_addr   = flow->dst_addr,
                                          .generation = flow->pause_generation,
                                          .src_port   = flow->src_port,
                                          .dst_port   = flow->dst_port,
                                          .force      = force,
    };
    return context;
}

static void smugglefintrickReleaseQueuedPacketsNow(tunnel_t *t, line_t *l,
                                                   const smugglefintrick_release_context_t *context)
{
    ipmanipulator_tstate_t                    *state                = tunnelGetState(t);
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets       = NULL;
    uint32_t                                   queued_packets_count = 0;
    uint64_t                                   now_ms               = getTickMS();

    assert(lineGetWID(l) == getWID());

    mutexLock(&state->smuggle_fin_mutex);

    ipmanipulator_smuggle_fin_flow_t *flow = smugglefintrickFindReleaseFlowLocked(state, context);
    if (flow == NULL || ! flow->paused || flow->pause_generation != context->generation ||
        (! context->force && ! flow->release_pending))
    {
        mutexUnlock(&state->smuggle_fin_mutex);
        return;
    }

    if (context->force)
    {
        LOGW("IpManipulator: smuggle-fin pause timed out after %u ms; releasing the flow",
             state->trick_smuggle_fin_pause_timeout_ms);
    }

    smugglefintrickDetachQueuedPacketsLocked(flow, context->force, now_ms, &queued_packets, &queued_packets_count);

    mutexUnlock(&state->smuggle_fin_mutex);

    if (queued_packets_count > 0)
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

    tunnel_t                          *t       = arg1;
    line_t                            *l       = arg2;
    smugglefintrick_release_context_t *context = arg3;

    if (lineIsAlive(l))
    {
        smugglefintrickReleaseQueuedPacketsNow(t, l, context);
    }

    memoryFree(context);
    lineUnlock(l);
}

static void smugglefintrickCleanupDelayedRelease(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    memoryFree(arg3);
    lineUnlock((line_t *) arg2);
}

static void smugglefintrickScheduleQueuedRelease(tunnel_t *t, line_t *l, uint32_t delay_ms,
                                                 smugglefintrick_release_context_t *context)
{
    if (delay_ms == 0 && getWID() == lineGetWID(l))
    {
        smugglefintrickReleaseQueuedPacketsNow(t, l, context);
        memoryFree(context);
        return;
    }

    lineLock(l);
#ifdef IPMANIPULATOR_SMUGGLEFIN_TEST_HOOKS
    ipmanipulatorSmuggleFinTestScheduleTimed(lineGetWID(l),
                                             (WorkerMessageCallback) smugglefintrickRunDelayedRelease,
                                             smugglefintrickCleanupDelayedRelease,
                                             delay_ms,
                                             t,
                                             l,
                                             context);
#else
    sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                      (WorkerMessageCallback) smugglefintrickRunDelayedRelease,
                                      smugglefintrickCleanupDelayedRelease,
                                      delay_ms,
                                      t,
                                      l,
                                      context);
#endif
}

static void smugglefintrickForceReleaseAfterQueueLimit(tunnel_t *t, line_t *l,
                                                       ipmanipulator_smuggle_fin_queued_packet_t *queued_packets,
                                                       uint32_t                                   queued_packets_count)
{
    LOGW("IpManipulator: smuggle-fin paused-flow queue reached its %u-packet limit; releasing the flow",
         kSmuggleFinMaxQueueCapacity);

    if (queued_packets_count > 0)
    {
        smugglefintrickFlushQueuedPackets(t, l, queued_packets, queued_packets_count);
    }
    else
    {
        memoryFree(queued_packets);
    }
}

bool smugglefintrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineGetWID(l) == getWID());

    ipmanipulator_tstate_t                    *state                = tunnelGetState(t);
    smugglefintrick_tcp_packet_info_t          info                 = {0};
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets       = NULL;
    uint32_t                                   queued_packets_count = 0;
    uint64_t                                   now_ms               = getTickMS();

    if (state->trick_real_fin_upstream_tunnel == NULL)
    {
        return false;
    }

    /*
     * A pause belongs to one parseable TCP flow. Unparseable packets and every
     * unrelated flow continue normally instead of being held behind it.
     */
    if (! smugglefintrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    mutexLock(&state->smuggle_fin_mutex);

    bool                              worker_has_paused_flow = false;
    ipmanipulator_smuggle_fin_flow_t *flow =
        smugglefintrickInspectUpstreamFlowsLocked(state, &info, now_ms, lineGetWID(l), &worker_has_paused_flow);
    if (flow != NULL)
    {
        flow->last_activity_ms = now_ms;

        if (flow->paused)
        {
            if (smugglefintrickQueuePacketLocked(flow, buf, kIpManipulatorSmuggleFinQueueDirectionUpstream))
            {
                mutexUnlock(&state->smuggle_fin_mutex);
                return true;
            }

            smugglefintrickDetachQueuedPacketsLocked(flow, true, now_ms, &queued_packets, &queued_packets_count);
            mutexUnlock(&state->smuggle_fin_mutex);
            smugglefintrickForceReleaseAfterQueueLimit(t, l, queued_packets, queued_packets_count);
            return false;
        }

        if (flow->confirmed)
        {
            mutexUnlock(&state->smuggle_fin_mutex);
            return false;
        }
    }

    if ((flow == NULL && worker_has_paused_flow) || ! smugglefintrickShouldMirror(&info))
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

    flow->last_activity_ms  = now_ms;
    flow->paused_at_ms      = now_ms;
    flow->expected_src_addr = info.dst_addr;
    flow->expected_dst_addr = info.src_addr;
    flow->expected_src_port = info.dst_port;
    flow->expected_dst_port = info.src_port;
    flow->expected_seq      = info.ack;
    flow->expected_ack      = info.seq + smugglefintrickAckAdvance(&info);
    flow->line              = l;
    flow->release_pending   = false;
    flow->paused            = true;
    /*
     * Allocate generations across the whole tunnel so zeroing and reusing a
     * flow slot cannot let an old delayed-release context match a new occupant.
     */
    state->smuggle_fin_next_pause_generation += 1U;
    if (state->smuggle_fin_next_pause_generation == 0)
    {
        state->smuggle_fin_next_pause_generation = 1;
    }
    flow->pause_generation = state->smuggle_fin_next_pause_generation;

    if (! smugglefintrickQueuePacketLocked(flow, buf, kIpManipulatorSmuggleFinQueueDirectionUpstream))
    {
        smugglefintrickDetachQueuedPacketsLocked(flow, true, now_ms, &queued_packets, &queued_packets_count);
        mutexUnlock(&state->smuggle_fin_mutex);
        lineReuseBuffer(l, fin_packet);
        smugglefintrickForceReleaseAfterQueueLimit(t, l, queued_packets, queued_packets_count);
        return false;
    }

    smugglefintrick_release_context_t *timeout_context  = smugglefintrickCreateReleaseContextLocked(flow, true);
    uint32_t                           pause_generation = flow->pause_generation;

    mutexUnlock(&state->smuggle_fin_mutex);

    smugglefintrickScheduleQueuedRelease(t, l, state->trick_smuggle_fin_pause_timeout_ms, timeout_context);

    bool original_recalculate_checksum = lineGetRecalculateChecksum(l);

    lineLock(l);
    lineSetRecalculateChecksum(l, true);

    /*
     * The mirrored-FIN helper peer expects the original tuple. Apply the normal
     * checksum/protocol ordering without adding a portghost trailer.
     */
    ipmanipulatorEmitUpstreamPreservingTuple(t, l, fin_packet, smugglefintrickForwardRealFin);

    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        LOGF("IpManipulator: worker packet line died during smuggle-fin send");
        abortProgramNow(1);
    }

    lineSetRecalculateChecksum(l, original_recalculate_checksum);
    lineUnlock(l);

    LOGD("IpManipulator: smuggle-fin sent a mirrored FIN packet to \"%s\" and paused flow generation %u",
         state->trick_real_fin_upstream_node != NULL ? state->trick_real_fin_upstream_node->name : "(null)",
         pause_generation);

    return true;
}

bool smugglefintrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineGetWID(l) == getWID());

    ipmanipulator_tstate_t                    *state                = tunnelGetState(t);
    smugglefintrick_tcp_packet_info_t          info                 = {0};
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets       = NULL;
    uint32_t                                   queued_packets_count = 0;
    uint64_t                                   now_ms               = getTickMS();

    /*
     * Unparseable packets cannot belong to a known paused 4-tuple, so they pass
     * through. This prevents one malformed packet from stalling any flow.
     */
    if (! smugglefintrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    mutexLock(&state->smuggle_fin_mutex);

    ipmanipulator_smuggle_fin_flow_t *expected_flow = NULL;
    ipmanipulator_smuggle_fin_flow_t *reverse_flow  = NULL;
    smugglefintrickInspectDownstreamFlowsLocked(state, &info, now_ms, &expected_flow, &reverse_flow);

    ipmanipulator_smuggle_fin_flow_t *flow = expected_flow;
    if (flow != NULL)
    {
        flow->last_activity_ms = now_ms;

        if (flow->release_pending)
        {
            mutexUnlock(&state->smuggle_fin_mutex);
            lineReuseBuffer(l, buf);
            return true;
        }

        flow->confirmed       = true;
        flow->release_pending = true;

        line_t                            *owner_line       = flow->line;
        smugglefintrick_release_context_t *release_context  = smugglefintrickCreateReleaseContextLocked(flow, false);
        uint32_t                           release_delay_ms = state->trick_smuggle_fin_delay_ms;

        mutexUnlock(&state->smuggle_fin_mutex);

        lineReuseBuffer(l, buf);

        LOGD("IpManipulator: received the expected smuggle-fin echo and will release its flow after %u ms",
             release_delay_ms);
        smugglefintrickScheduleQueuedRelease(t, owner_line, release_delay_ms, release_context);
        return true;
    }

    flow = reverse_flow;
    if (flow != NULL)
    {
        if (flow->paused)
        {
            line_t *owner_line = flow->line;
            if (owner_line == NULL || lineGetWID(owner_line) != lineGetWID(l))
            {
                mutexUnlock(&state->smuggle_fin_mutex);
                return false;
            }

            flow->last_activity_ms = now_ms;

            if (smugglefintrickQueuePacketLocked(flow, buf, kIpManipulatorSmuggleFinQueueDirectionDownstream))
            {
                mutexUnlock(&state->smuggle_fin_mutex);
                return true;
            }

            smugglefintrickDetachQueuedPacketsLocked(flow, true, now_ms, &queued_packets, &queued_packets_count);
            mutexUnlock(&state->smuggle_fin_mutex);
            smugglefintrickForceReleaseAfterQueueLimit(t, owner_line, queued_packets, queued_packets_count);
            return false;
        }

        flow->last_activity_ms = now_ms;
    }

    mutexUnlock(&state->smuggle_fin_mutex);
    return false;
}

void smugglefintrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state->smuggle_fin_flows == NULL)
    {
        return;
    }

    mutexLock(&state->smuggle_fin_mutex);

    for (uint32_t i = 0; i < state->smuggle_fin_flows_capacity; ++i)
    {
        smugglefintrickDestroyFlow(&state->smuggle_fin_flows[i]);
    }

    mutexUnlock(&state->smuggle_fin_mutex);
    mutexDestroy(&state->smuggle_fin_mutex);

    memoryFree(state->smuggle_fin_flows);
    state->smuggle_fin_flows          = NULL;
    state->smuggle_fin_flows_capacity = 0;
}
