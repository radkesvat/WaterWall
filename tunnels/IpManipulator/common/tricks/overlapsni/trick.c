#include "trick.h"

#include "TlsClient/interface.h"
#include "loggers/network_logger.h"

enum
{
    kOverlapSniWarmupPackets             = 2,
    kOverlapSniDelayWindowMs             = 5U * 1000U,
    kOverlapSniDelaySequenceSpacingMs    = 2U,
    kOverlapSniIdleTimeoutMs             = 20U * 60U * 1000U,
    kOverlapSniGeneratedHelloMaxLen      = 900U,
    kOverlapSniMaxEmittedPackets         = 5U,
    kOverlapSniContinuationPreserveFlags = (TCP_CWR | TCP_ECE | TCP_URG | TCP_ACK)
};

typedef struct overlapsnitrick_tcp_packet_info_s
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
} overlapsnitrick_tcp_packet_info_t;

typedef struct overlapsnitrick_packet_sequence_s
{
    sbuf_t *packets[kOverlapSniMaxEmittedPackets];
    uint8_t count;
} overlapsnitrick_packet_sequence_t;

typedef struct overlapsnitrick_handle_result_s
{
    bool                              block_flow;
    bool                              start_delay_window;
    overlapsnitrick_packet_sequence_t normal_sequence;
} overlapsnitrick_handle_result_t;

typedef struct overlapsnitrick_hold_timeout_s
{
    ipmanipulator_flow_key_t key;
    uint64_t                 generation;
} overlapsnitrick_hold_timeout_t;

#ifdef IPMANIPULATOR_OVERLAP_TEST_HOOKS
bool ipmanipulatorOverlapTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                           WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                           void *arg2, void *arg3);
#endif

static void overlapsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf);

static void overlapsnitrickDestroyCapturedPacket(ipmanipulator_captured_packet_t *packet)
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

static void overlapsnitrickRecycleCapturedPacket(ipmanipulator_captured_packet_t *packet)
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

static void overlapsnitrickDestroyPacketSequence(overlapsnitrick_packet_sequence_t *sequence)
{
    if (sequence == NULL)
    {
        return;
    }

    for (uint8_t i = 0; i < sequence->count; ++i)
    {
        if (sequence->packets[i] != NULL)
        {
            sbufDestroy(sequence->packets[i]);
            sequence->packets[i] = NULL;
        }
    }

    sequence->count = 0;
}

/* The caller owns the record's retained line reference after a successful take. */
static bool overlapsnitrickTakeHeldPacketLocked(ipmanipulator_overlap_flow_t    *flow,
                                                ipmanipulator_captured_packet_t *held_packet)
{
    if (flow == NULL || held_packet == NULL)
    {
        return false;
    }

    *held_packet           = flow->held_packet;
    flow->held_packet      = (ipmanipulator_captured_packet_t) {0};
    flow->held_wid         = kInvalidWID;
    flow->hold_timer_armed = false;
    flow->hold_generation  = 0;
    return held_packet->line != NULL || held_packet->buf != NULL;
}

static void overlapsnitrickDestroyHeldPacketLocked(ipmanipulator_overlap_flow_t *flow)
{
    ipmanipulator_captured_packet_t held_packet = {0};

    if (! overlapsnitrickTakeHeldPacketLocked(flow, &held_packet))
    {
        return;
    }

    line_t *held_line = held_packet.line;
    overlapsnitrickDestroyCapturedPacket(&held_packet);
    if (held_line != NULL)
    {
        lineUnref(held_line);
    }
}

static void overlapsnitrickResetFlow(ipmanipulator_overlap_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    uint64_t barrier_generation = flow->delay_barrier.generation;
    memoryZero(flow, sizeof(*flow));
    flow->delay_barrier.generation = barrier_generation;
    flow->held_wid                 = kInvalidWID;
}

static void overlapsnitrickDestroyFlow(ipmanipulator_overlap_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    overlapsnitrickDestroyHeldPacketLocked(flow);
    ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
    overlapsnitrickResetFlow(flow);
}

static void overlapsnitrickInitializeFlow(ipmanipulator_overlap_flow_t            *flow,
                                          const overlapsnitrick_tcp_packet_info_t *info, uint64_t now_ms)
{
    if (flow == NULL || info == NULL)
    {
        return;
    }

    overlapsnitrickDestroyHeldPacketLocked(flow);
    ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
    overlapsnitrickResetFlow(flow);

    *flow = (ipmanipulator_overlap_flow_t) {
        .created_ms       = now_ms,
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .phase            = kIpManipulatorOverlapFlowPhaseWarmup,
        .held_wid         = kInvalidWID,
    };
}

static void overlapsnitrickFinalizeFlowLocked(ipmanipulator_tstate_t *state, ipmanipulator_overlap_flow_t *flow,
                                              bool block_flow, const overlapsnitrick_handle_result_t *result,
                                              uint64_t now_ms, uint32_t configured_delay_ms)
{
    if (flow == NULL)
    {
        return;
    }

    overlapsnitrickDestroyHeldPacketLocked(flow);
    flow->warmup_packets_seen = kOverlapSniWarmupPackets;
    flow->phase = block_flow ? kIpManipulatorOverlapFlowPhaseBlocked : kIpManipulatorOverlapFlowPhasePassthrough;
    uint64_t transcript_delay_ms =
        (uint64_t) configured_delay_ms +
        ((uint64_t) (kOverlapSniMaxEmittedPackets - 3U) * kOverlapSniDelaySequenceSpacingMs) + 1U;
    flow->delay_window_until_ms = (result != NULL && result->start_delay_window && ! block_flow)
                                      ? now_ms + max((uint64_t) kOverlapSniDelayWindowMs, transcript_delay_ms)
                                      : 0;
    ipmanipulatorDelayBarrierInitialize(state, &flow->delay_barrier, flow->delay_window_until_ms);
}

static bool overlapsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                              overlapsnitrick_tcp_packet_info_t *info)
{
    ipv4_packet_view_t packet_view = {0};
    if (info == NULL || ! ipv4packetviewParseTcp(packet, packet_length, &packet_view) || packet_view.fragmented)
    {
        return false;
    }

    *info = (overlapsnitrick_tcp_packet_info_t) {
        .packet            = packet,
        .seq               = packet_view.tcp_sequence,
        .payload_offset    = packet_view.payload_offset,
        .ip_total_len      = packet_view.ip_total_length,
        .ip_header_len     = packet_view.ip_header_length,
        .tcp_header_len    = packet_view.transport_header_length,
        .headers_len       = packet_view.payload_offset,
        .tcp_payload_len   = packet_view.payload_length,
        .src_port          = packet_view.source_port,
        .dst_port          = packet_view.destination_port,
        .ip_identification = packet_view.ip_identification,
        .src_addr          = packet_view.source_address,
        .dst_addr          = packet_view.destination_address,
        .tcp_flags         = packet_view.tcp_flags,
    };

    return true;
}

static bool overlapsnitrickIsPureSyn(const overlapsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && ipmanipulatorIsFlowOpeningSyn(info->tcp_flags, info->tcp_payload_len);
}

static bool overlapsnitrickHasFinOrRst(const overlapsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static ipmanipulator_flow_key_t overlapsnitrickMakeKey(const overlapsnitrick_tcp_packet_info_t *info)
{
    return ipmanipulatorFlowKeyMake(info->src_addr, info->src_port, info->dst_addr, info->dst_port);
}

static ipmanipulator_overlap_flow_t *overlapsnitrickEntryRecord(ipmanipulator_flow_entry_t *entry)
{
    return (ipmanipulator_overlap_flow_t *) ipmanipulatorFlowEntryRecord(entry);
}

/* The record keeps the client-to-server orientation the transcript logic uses. */
static bool overlapsnitrickFlowIsForward(const ipmanipulator_overlap_flow_t      *flow,
                                         const overlapsnitrick_tcp_packet_info_t *info)
{
    return flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr && flow->src_port == info->src_port &&
           flow->dst_port == info->dst_port;
}

static ipmanipulator_flow_shard_t *overlapsnitrickLockShard(ipmanipulator_tstate_t         *state,
                                                            const ipmanipulator_flow_key_t *key, uint64_t now_ms)
{
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->overlap_table, key);

    if (shard != NULL)
    {
        discard ipmanipulatorFlowShardExpire(&state->overlap_table, shard, now_ms, kIpManipulatorFlowCleanupBudget);
    }

    return shard;
}

static void overlapsnitrickTouchLocked(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                       uint64_t now_ms)
{
    overlapsnitrickEntryRecord(entry)->last_activity_ms = now_ms;
    ipmanipulatorFlowShardTouch(shard, entry, now_ms + kOverlapSniIdleTimeoutMs);
}

static ipmanipulator_flow_entry_t *overlapsnitrickFindLocked(ipmanipulator_tstate_t                  *state,
                                                             ipmanipulator_flow_shard_t              *shard,
                                                             const ipmanipulator_flow_key_t          *key,
                                                             const overlapsnitrick_tcp_packet_info_t *info,
                                                             bool                                     want_forward)
{
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->overlap_table, shard, key);

    if (entry != NULL && overlapsnitrickFlowIsForward(overlapsnitrickEntryRecord(entry), info) != want_forward)
    {
        return NULL;
    }

    return entry;
}

static ipmanipulator_flow_entry_t *overlapsnitrickReserveLocked(ipmanipulator_tstate_t                  *state,
                                                                ipmanipulator_flow_shard_t              *shard,
                                                                const ipmanipulator_flow_key_t          *key,
                                                                const overlapsnitrick_tcp_packet_info_t *info,
                                                                uint64_t                                 now_ms)
{
    ipmanipulator_flow_entry_t *entry =
        ipmanipulatorFlowShardReserve(&state->overlap_table, shard, key, now_ms, now_ms + kOverlapSniIdleTimeoutMs);

    if (entry == NULL)
    {
        return NULL;
    }

    overlapsnitrickInitializeFlow(overlapsnitrickEntryRecord(entry), info, now_ms);
    return entry;
}

static void overlapsnitrickReleaseTimedOutHold(tunnel_t *t, const ipmanipulator_flow_key_t *key, uint64_t generation)
{
    ipmanipulator_tstate_t         *state       = tunnelGetState(t);
    ipmanipulator_captured_packet_t held_packet = {0};
    ipmanipulator_flow_shard_t     *shard       = ipmanipulatorFlowTableLockShard(&state->overlap_table, key);

    if (shard != NULL)
    {
        ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->overlap_table, shard, key);

        if (entry != NULL)
        {
            ipmanipulator_overlap_flow_t *flow = overlapsnitrickEntryRecord(entry);

            if (flow->phase == kIpManipulatorOverlapFlowPhaseHoldThird && flow->hold_timer_armed &&
                flow->hold_generation == generation)
            {
                discard overlapsnitrickTakeHeldPacketLocked(flow, &held_packet);
                flow->phase = kIpManipulatorOverlapFlowPhasePassthrough;
                overlapsnitrickTouchLocked(shard, entry, getTickMS());
            }
        }

        ipmanipulatorFlowShardUnlock(shard);
    }

    if (held_packet.line != NULL || held_packet.buf != NULL)
    {
        LOGD("IpManipulator: overlap-sni hold timed out after %u ms; releasing the segment unchanged",
             state->trick_overlap_sni_hold_timeout_ms);

        line_t *held_line = held_packet.line;
        if (held_line != NULL && held_packet.buf != NULL)
        {
            overlapsnitrickSendNormalNow(t, held_line, held_packet.buf);
        }
        else if (held_packet.buf != NULL)
        {
            sbufDestroy(held_packet.buf);
        }

        if (held_line != NULL)
        {
            lineUnref(held_line);
        }
    }
}

static void overlapsnitrickRunHoldTimeout(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;

    tunnel_t                       *t       = arg1;
    line_t                         *l       = arg2;
    overlapsnitrick_hold_timeout_t *context = arg3;

    overlapsnitrickReleaseTimedOutHold(t, &context->key, context->generation);
    memoryFree(context);
    lineUnref(l);
}

static void overlapsnitrickCleanupHoldTimeout(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                         reason;
    tunnel_t                       *t       = arg1;
    line_t                         *l       = arg2;
    overlapsnitrick_hold_timeout_t *context = arg3;

    if (lineIsOnCurrentEventWorker(l))
    {
        overlapsnitrickReleaseTimedOutHold(t, &context->key, context->generation);
    }
    memoryFree(context);
    lineUnref(l);
}

static bool overlapsnitrickScheduleHoldTimeout(tunnel_t *t, line_t *l, const ipmanipulator_flow_key_t *key,
                                               uint64_t generation, uint32_t delay_ms)
{
    /* Configuration rejects zero; keep direct/internal state fail-open too. */
    delay_ms                     = max(delay_ms, 1U);
    const bool recover_on_caller = lineIsOnCurrentEventWorker(l);

    overlapsnitrick_hold_timeout_t *context = memoryAllocate(sizeof(*context));
    if (context == NULL)
    {
        if (recover_on_caller)
        {
            overlapsnitrickReleaseTimedOutHold(t, key, generation);
        }
        return false;
    }

    *context = (overlapsnitrick_hold_timeout_t) {
        .key        = *key,
        .generation = generation,
    };

    /* The queued message owns a separate reference from the held flow record. */
    lineRef(l);
#ifdef IPMANIPULATOR_OVERLAP_TEST_HOOKS
    bool scheduled = ipmanipulatorOverlapTestScheduleTimed(lineGetWID(l),
                                                           (WorkerMessageCallback) overlapsnitrickRunHoldTimeout,
                                                           overlapsnitrickCleanupHoldTimeout,
                                                           delay_ms,
                                                           t,
                                                           l,
                                                           context);
#else
    bool scheduled = sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                                       (WorkerMessageCallback) overlapsnitrickRunHoldTimeout,
                                                       overlapsnitrickCleanupHoldTimeout,
                                                       delay_ms,
                                                       t,
                                                       l,
                                                       context) == kWorkerMessageSubmitAccepted;
#endif
    if (! scheduled && recover_on_caller)
    {
        overlapsnitrickReleaseTimedOutHold(t, key, generation);
    }
    return scheduled;
}

static sbuf_t *overlapsnitrickGenerateTlsClientHello(tunnel_t *t, line_t *l)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    return tlsclientTunnelGenerateClientHello(state->trick_overlap_sni_tls_client_tunnel,
                                              l,
                                              (const uint8_t *) state->trick_overlap_sni_value,
                                              state->trick_overlap_sni_value_len);
}

static sbuf_t *overlapsnitrickBuildCombinedPacket(line_t *l, const ipmanipulator_captured_packet_t *held_packet,
                                                  const overlapsnitrick_tcp_packet_info_t *held_info,
                                                  const overlapsnitrick_tcp_packet_info_t *current_info)
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

static sbuf_t *overlapsnitrickBuildPacketFromTemplate(line_t *l, sbuf_t *template_buf,
                                                      const overlapsnitrick_tcp_packet_info_t *template_info,
                                                      const uint8_t *payload, uint32_t payload_len, uint32_t seq,
                                                      uint16_t ip_identification, uint8_t tcp_flags)
{
    if (l == NULL || template_buf == NULL || template_info == NULL || payload == NULL || payload_len == 0)
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
    memoryCopyLarge(packet + template_info->headers_len, payload, payload_len);

    struct ip_hdr  *ipheader  = (struct ip_hdr *) packet;
    struct tcp_hdr *tcpheader = (struct tcp_hdr *) (packet + template_info->ip_header_len);

    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) packet_len));
    IPH_ID_SET(ipheader, lwip_htons(ip_identification));
    IPH_OFFSET_SET(ipheader, lwip_htons((uint16_t) (lwip_ntohs(IPH_OFFSET(ipheader)) & ~(IP_MF | IP_OFFMASK))));
    tcpheader->seqno = lwip_htonl(seq);
    TCPH_FLAGS_SET(tcpheader, tcp_flags);

    return result;
}

static sbuf_t *overlapsnitrickBuildFakeSynPacket(tunnel_t *t, line_t *l,
                                                 const ipmanipulator_captured_packet_t   *held_packet,
                                                 const overlapsnitrick_tcp_packet_info_t *held_info,
                                                 uint16_t                                 ip_identification)
{
    if (t == NULL || l == NULL || held_packet == NULL || held_packet->buf == NULL || held_info == NULL)
    {
        return NULL;
    }

    sbuf_t *syn_packet = clonePacketWithLength(l, held_packet->buf, held_info->headers_len);
    if (syn_packet == NULL)
    {
        return NULL;
    }

    sbufSetLength(syn_packet, held_info->headers_len);
    memoryCopyLarge(sbufGetMutablePtr(syn_packet), held_info->packet, held_info->headers_len);

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    uint8_t                *packet     = sbufGetMutablePtr(syn_packet);
    struct ip_hdr          *ipheader   = (struct ip_hdr *) packet;
    struct tcp_hdr         *tcp_header = (struct tcp_hdr *) (packet + held_info->ip_header_len);

    IPH_LEN_SET(ipheader, lwip_htons(held_info->headers_len));
    IPH_ID_SET(ipheader, lwip_htons(ip_identification));
    IPH_OFFSET_SET(ipheader, lwip_htons((uint16_t) (lwip_ntohs(IPH_OFFSET(ipheader)) & ~(IP_MF | IP_OFFMASK))));

    if (state->trick_overlap_sni_syn_ttl >= 0)
    {
        IPH_TTL_SET(ipheader, (uint8_t) state->trick_overlap_sni_syn_ttl);
    }

    tcp_header->seqno = lwip_htonl((lwip_ntohl(tcp_header->seqno) - 1));
    tcp_header->ackno = 0;
    TCPH_FLAGS_SET(tcp_header, TCP_SYN);

    return syn_packet;
}

static bool overlapsnitrickAppendPacket(overlapsnitrick_packet_sequence_t *sequence, sbuf_t *packet)
{
    if (sequence == NULL || packet == NULL || sequence->count >= kOverlapSniMaxEmittedPackets)
    {
        return false;
    }

    sequence->packets[sequence->count++] = packet;
    return true;
}

static uint8_t overlapsnitrickGetContinuationFlags(uint8_t original_flags)
{
    return (uint8_t) (original_flags & kOverlapSniContinuationPreserveFlags);
}

static bool overlapsnitrickBuildPacketSequence(tunnel_t *t, line_t *l,
                                               const ipmanipulator_captured_packet_t   *held_packet,
                                               const overlapsnitrick_tcp_packet_info_t *held_info, sbuf_t *current_buf,
                                               const overlapsnitrick_tcp_packet_info_t *current_info,
                                               const uint8_t *real_combined_payload, const uint8_t *generated_payload,
                                               uint32_t                           generated_payload_len,
                                               overlapsnitrick_packet_sequence_t *sequence)
{
    if (t == NULL || l == NULL || held_packet == NULL || held_info == NULL || current_buf == NULL ||
        current_info == NULL || real_combined_payload == NULL || generated_payload == NULL || sequence == NULL)
    {
        return false;
    }

    uint32_t real_combined_payload_len =
        (uint32_t) held_info->tcp_payload_len + (uint32_t) current_info->tcp_payload_len;
    if (generated_payload_len == 0 || generated_payload_len > real_combined_payload_len)
    {
        return false;
    }

    uint16_t next_ip_id = held_info->ip_identification;

    sbuf_t *packet_y = overlapsnitrickBuildPacketFromTemplate(l,
                                                              held_packet->buf,
                                                              held_info,
                                                              real_combined_payload,
                                                              generated_payload_len,
                                                              held_info->seq,
                                                              next_ip_id++,
                                                              held_info->tcp_flags);
    if (! overlapsnitrickAppendPacket(sequence, packet_y))
    {
        if (packet_y != NULL)
        {
            sbufDestroy(packet_y);
        }
        return false;
    }

    sbuf_t *packet_syn = overlapsnitrickBuildFakeSynPacket(t, l, held_packet, held_info, next_ip_id++);
    if (! overlapsnitrickAppendPacket(sequence, packet_syn))
    {
        if (packet_syn != NULL)
        {
            sbufDestroy(packet_syn);
        }
        overlapsnitrickDestroyPacketSequence(sequence);
        return false;
    }

    sbuf_t *packet_x = overlapsnitrickBuildPacketFromTemplate(l,
                                                              held_packet->buf,
                                                              held_info,
                                                              generated_payload,
                                                              generated_payload_len,
                                                              held_info->seq,
                                                              next_ip_id++,
                                                              held_info->tcp_flags);
    if (! overlapsnitrickAppendPacket(sequence, packet_x))
    {
        if (packet_x != NULL)
        {
            sbufDestroy(packet_x);
        }
        overlapsnitrickDestroyPacketSequence(sequence);
        return false;
    }

    uint32_t remaining_offset = generated_payload_len;
    uint32_t fourth_offset =
        remaining_offset > held_info->tcp_payload_len ? remaining_offset - held_info->tcp_payload_len : 0;
    bool have_fourth_tail = fourth_offset < current_info->tcp_payload_len;

    if (remaining_offset < held_info->tcp_payload_len)
    {
        uint32_t third_tail_len = held_info->tcp_payload_len - remaining_offset;
        uint8_t  third_tail_flags =
            have_fourth_tail ? overlapsnitrickGetContinuationFlags(held_info->tcp_flags) : held_info->tcp_flags;

        sbuf_t *third_tail = overlapsnitrickBuildPacketFromTemplate(l,
                                                                    held_packet->buf,
                                                                    held_info,
                                                                    real_combined_payload + remaining_offset,
                                                                    third_tail_len,
                                                                    held_info->seq + remaining_offset,
                                                                    next_ip_id++,
                                                                    third_tail_flags);
        if (! overlapsnitrickAppendPacket(sequence, third_tail))
        {
            if (third_tail != NULL)
            {
                sbufDestroy(third_tail);
            }
            overlapsnitrickDestroyPacketSequence(sequence);
            return false;
        }
    }

    if (have_fourth_tail)
    {
        uint32_t fourth_tail_len = current_info->tcp_payload_len - fourth_offset;
        sbuf_t  *fourth_tail =
            overlapsnitrickBuildPacketFromTemplate(l,
                                                   current_buf,
                                                   current_info,
                                                   real_combined_payload + held_info->tcp_payload_len + fourth_offset,
                                                   fourth_tail_len,
                                                   current_info->seq + fourth_offset,
                                                   next_ip_id++,
                                                   current_info->tcp_flags);
        if (! overlapsnitrickAppendPacket(sequence, fourth_tail))
        {
            if (fourth_tail != NULL)
            {
                sbufDestroy(fourth_tail);
            }
            overlapsnitrickDestroyPacketSequence(sequence);
            return false;
        }
    }

    return sequence->count >= 3;
}

static bool overlapsnitrickSendUpstreamDirect(tunnel_t *t, line_t *l, sbuf_t *buf)
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

    lineSetRecalculateChecksum(l, true);
    ipmanipulatorEmitUpstream(t, l, buf, tunnelNextUpStreamPayload);
    return lineIsAlive(l);
}

static void overlapsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    /* Stateful-SNI validation forbids same-instance packet duplication. */
    discard overlapsnitrickSendUpstreamDirect(t, l, buf);
}

static void overlapsnitrickSendHeldThenCurrentNormal(tunnel_t *t, ipmanipulator_captured_packet_t *held_packet,
                                                     line_t *current_line, sbuf_t *current_buf)
{
    line_t *line = held_packet != NULL && held_packet->line != NULL ? held_packet->line : current_line;

    if (line == NULL)
    {
        if (held_packet != NULL)
        {
            overlapsnitrickDestroyCapturedPacket(held_packet);
        }

        if (current_buf != NULL)
        {
            sbufDestroy(current_buf);
        }

        return;
    }

    lineRef(line);

    bool alive = lineIsAlive(line);

    if (held_packet != NULL && held_packet->buf != NULL)
    {
        if (alive)
        {
            alive = overlapsnitrickSendUpstreamDirect(t, line, held_packet->buf);
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
            discard overlapsnitrickSendUpstreamDirect(t, line, current_buf);
        }
        else
        {
            lineReuseBuffer(line, current_buf);
        }
    }

    lineUnref(line);
}

static void overlapsnitrickSendOutputs(tunnel_t *t, line_t *l, overlapsnitrick_packet_sequence_t *normal_sequence)
{
    if (l == NULL || normal_sequence == NULL)
    {
        overlapsnitrickDestroyPacketSequence(normal_sequence);
        return;
    }

    lineRef(l);

    bool alive = lineIsAlive(l);

    if (normal_sequence->count > 0 && normal_sequence->packets[0] != NULL)
    {
        if (alive)
        {
            alive = overlapsnitrickSendUpstreamDirect(t, l, normal_sequence->packets[0]);
        }
        else
        {
            lineReuseBuffer(l, normal_sequence->packets[0]);
        }
        normal_sequence->packets[0] = NULL;
    }

    if (normal_sequence->count > 1 && normal_sequence->packets[1] != NULL)
    {
        if (alive)
        {
            alive = overlapsnitrickSendUpstreamDirect(t, l, normal_sequence->packets[1]);
        }
        else
        {
            lineReuseBuffer(l, normal_sequence->packets[1]);
        }
        normal_sequence->packets[1] = NULL;
    }

    for (uint8_t i = 2; i < normal_sequence->count; ++i)
    {
        sbuf_t *packet = normal_sequence->packets[i];
        if (packet == NULL)
        {
            continue;
        }

        if (alive)
        {
            alive = overlapsnitrickSendUpstreamDirect(t, l, packet);
        }
        else
        {
            lineReuseBuffer(l, packet);
        }

        normal_sequence->packets[i] = NULL;
    }

    normal_sequence->count = 0;
    lineUnref(l);
}

static void overlapsnitrickLogRejectedFlow(const sbuf_t *combined_packet, const sni_match_t *match,
                                           uint32_t real_sni_payload_offset, uint32_t generated_payload_len)
{
    const uint8_t *packet   = (const uint8_t *) sbufGetRawPtr((sbuf_t *) combined_packet);
    size_t         copy_len = min((size_t) match->sni_name_len, (size_t) 255U);
    char           sni_name[256];

    memoryZero(sni_name, sizeof(sni_name));
    memoryCopy(sni_name, packet + match->sni_name_offset, copy_len);

    LOGW("IpManipulator: overlap-sni rejected flow because real SNI \"%s\" begins at TLS payload offset %u before "
         "generated ClientHello length %u",
         sni_name,
         real_sni_payload_offset,
         generated_payload_len);
}

static bool overlapsnitrickHandleHeldPair(tunnel_t *t, line_t *l, ipmanipulator_captured_packet_t *held_packet,
                                          sbuf_t *current_buf, const overlapsnitrick_tcp_packet_info_t *current_info,
                                          overlapsnitrick_handle_result_t *result)
{
    overlapsnitrick_tcp_packet_info_t held_info = {0};

    if (result != NULL)
    {
        memoryZero(result, sizeof(*result));
    }

    if (held_packet == NULL || held_packet->buf == NULL || held_packet->line == NULL || current_buf == NULL ||
        current_info == NULL)
    {
        if (held_packet != NULL)
        {
            overlapsnitrickRecycleCapturedPacket(held_packet);
        }

        if (current_buf != NULL)
        {
            overlapsnitrickSendNormalNow(t, l, current_buf);
        }

        return true;
    }

    if (! overlapsnitrickParseTcpPacketInfo(
            (const uint8_t *) sbufGetRawPtr(held_packet->buf), sbufGetLength(held_packet->buf), &held_info))
    {
        overlapsnitrickRecycleCapturedPacket(held_packet);
        overlapsnitrickSendNormalNow(t, l, current_buf);
        return true;
    }

    if ((uint32_t) current_info->seq != held_info.seq + (uint32_t) held_info.tcp_payload_len ||
        held_info.tcp_payload_len == 0 || current_info->tcp_payload_len == 0)
    {
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *combined_packet =
        overlapsnitrickBuildCombinedPacket(held_packet->line, held_packet, &held_info, current_info);
    if (combined_packet == NULL)
    {
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *generated_hello = overlapsnitrickGenerateTlsClientHello(t, l);
    if (generated_hello == NULL)
    {
        sbufDestroy(combined_packet);
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    uint32_t generated_payload_len = sbufGetLength(generated_hello);
    uint32_t real_payload_len      = (uint32_t) held_info.tcp_payload_len + (uint32_t) current_info->tcp_payload_len;

    if (generated_payload_len == 0 || generated_payload_len > kOverlapSniGeneratedHelloMaxLen ||
        generated_payload_len > real_payload_len)
    {
        if (generated_payload_len > kOverlapSniGeneratedHelloMaxLen)
        {
            LOGW("IpManipulator: overlap-sni generated TLS ClientHello length %u exceeds supported limit %u",
                 generated_payload_len,
                 kOverlapSniGeneratedHelloMaxLen);
        }

        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sni_match_t match = {0};
    if (! parseClientHelloSni(
            (const uint8_t *) sbufGetRawPtr(combined_packet), sbufGetLength(combined_packet), &match) ||
        match.sni_name_offset < held_info.headers_len)
    {
        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    uint32_t real_sni_payload_offset = match.sni_name_offset - held_info.headers_len;
    if (real_sni_payload_offset < generated_payload_len)
    {
        overlapsnitrickLogRejectedFlow(combined_packet, &match, real_sni_payload_offset, generated_payload_len);

        if (result != NULL)
        {
            result->block_flow = true;
        }

        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        overlapsnitrickRecycleCapturedPacket(held_packet);
        lineReuseBuffer(l, current_buf);
        return true;
    }

    overlapsnitrick_packet_sequence_t sequence = {0};
    const uint8_t *combined_payload  = (const uint8_t *) sbufGetRawPtr(combined_packet) + held_info.headers_len;
    const uint8_t *generated_payload = (const uint8_t *) sbufGetRawPtr(generated_hello);

    if (! overlapsnitrickBuildPacketSequence(t,
                                             held_packet->line,
                                             held_packet,
                                             &held_info,
                                             current_buf,
                                             current_info,
                                             combined_payload,
                                             generated_payload,
                                             generated_payload_len,
                                             &sequence))
    {
        reuseBuffer(generated_hello);
        sbufDestroy(combined_packet);
        overlapsnitrickDestroyPacketSequence(&sequence);
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    if (result != NULL)
    {
        result->start_delay_window = true;
    }

    reuseBuffer(generated_hello);
    sbufDestroy(combined_packet);
    overlapsnitrickRecycleCapturedPacket(held_packet);
    lineReuseBuffer(l, current_buf);

    if (result != NULL)
    {
        result->normal_sequence = sequence;
    }
    else
    {
        overlapsnitrickSendOutputs(t, l, &sequence);
    }
    return true;
}

/* Runs under the shard lock: dispose only, never forward or call the tunnel. */
static void overlapsnitrickDestroyFlowRecord(void *record, void *context)
{
    discard context;

    overlapsnitrickDestroyFlow((ipmanipulator_overlap_flow_t *) record);
}

bool overlapsnitrickInitializeState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    return ipmanipulatorFlowTableInit(&state->overlap_table,
                                      "overlap-sni",
                                      state->trick_stateful_flow_limit,
                                      (uint32_t) getTotalWorkersCount(),
                                      sizeof(ipmanipulator_overlap_flow_t),
                                      overlapsnitrickDestroyFlowRecord,
                                      NULL);
}

void overlapsnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    ipmanipulatorFlowTableDestroy(&state->overlap_table);
}

bool overlapsnitrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));
    discard l;

    ipmanipulator_tstate_t           *state       = tunnelGetState(t);
    overlapsnitrick_tcp_packet_info_t info        = {0};
    uint64_t                          now_ms      = getTickMS();
    ipmanipulator_captured_packet_t   held_packet = {0};

    if (! overlapsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_flow_key_t    key   = overlapsnitrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = overlapsnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        return false;
    }

    /* Downstream traffic runs the reverse orientation of the stored record. */
    ipmanipulator_flow_entry_t *entry = overlapsnitrickFindLocked(state, shard, &key, &info, false);

    if (entry != NULL)
    {
        ipmanipulator_overlap_flow_t *flow = overlapsnitrickEntryRecord(entry);

        overlapsnitrickTouchLocked(shard, entry, now_ms);

        if (overlapsnitrickHasFinOrRst(&info))
        {
            discard overlapsnitrickTakeHeldPacketLocked(flow, &held_packet);
            ipmanipulatorFlowShardRemove(&state->overlap_table, shard, entry);
        }
    }

    ipmanipulatorFlowShardUnlock(shard);

    if (held_packet.line != NULL || held_packet.buf != NULL)
    {
        line_t *held_line = held_packet.line;

        if (held_line != NULL && held_packet.buf != NULL)
        {
            if (lineIsOnCurrentEventWorker(held_line))
            {
                overlapsnitrickSendNormalNow(t, held_line, held_packet.buf);
            }
            else
            {
                /*
                 * Cross-worker replay must first return to the held line's
                 * owner worker. Valid configuration still makes this a
                 * single-send path because packet duplication is incompatible
                 * with stateful SNI in the same instance.
                 */
                ipmanipulatorForwardCapturedPacketNormal(t, held_line, held_packet.buf);
            }
        }
        else if (held_packet.buf != NULL)
        {
            sbufDestroy(held_packet.buf);
        }

        if (held_line != NULL)
        {
            lineUnref(held_line);
        }
    }

    return false;
}

bool overlapsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));

    ipmanipulator_tstate_t           *state  = tunnelGetState(t);
    overlapsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                          now_ms = getTickMS();

    if (! overlapsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_captured_packet_t held_packet              = {0};
    bool                            bypass_current           = false;
    bool                            held_owner_mismatch      = false;
    ipmanipulator_delay_batch_t     release_batch            = {0};
    bool                            needs_schedule           = false;
    bool                            send_current_after_batch = false;
    uint64_t                        barrier_generation       = 0;
    uint64_t                        barrier_deadline         = 0;
    wid_t                           barrier_owner_wid        = kInvalidWID;
    wid_t                           transcript_owner_wid     = kInvalidWID;

    ipmanipulator_flow_key_t    key   = overlapsnitrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = overlapsnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        return false;
    }

    bool                        opening_syn = overlapsnitrickIsPureSyn(&info);
    ipmanipulator_flow_entry_t *entry       = ipmanipulatorFlowShardFind(&state->overlap_table, shard, &key);

    if (entry != NULL && opening_syn)
    {
        overlapsnitrickInitializeFlow(overlapsnitrickEntryRecord(entry), &info, now_ms);
    }
    else if (entry != NULL && ! overlapsnitrickFlowIsForward(overlapsnitrickEntryRecord(entry), &info))
    {
        entry = NULL;
    }

    if (entry == NULL)
    {
        if (! opening_syn)
        {
            ipmanipulatorFlowShardUnlock(shard);
            return false;
        }

        entry = overlapsnitrickReserveLocked(state, shard, &key, &info, now_ms);
    }

    if (entry == NULL)
    {
        ipmanipulatorFlowShardUnlock(shard);
        LOGW("IpManipulator: overlap-sni could not admit a flow record; the packet passes unchanged");
        return false;
    }

    ipmanipulator_overlap_flow_t *flow = overlapsnitrickEntryRecord(entry);

    overlapsnitrickTouchLocked(shard, entry, now_ms);

    if (flow->phase == kIpManipulatorOverlapFlowPhaseBlocked)
    {
        if (overlapsnitrickHasFinOrRst(&info))
        {
            ipmanipulatorFlowShardRemove(&state->overlap_table, shard, entry);
        }

        ipmanipulatorFlowShardUnlock(shard);
        lineReuseBuffer(l, buf);
        return true;
    }

    bool transcript_pending = ipmanipulatorDelayBarrierHasPendingOrdered(&flow->delay_barrier);
    if (flow->phase == kIpManipulatorOverlapFlowPhasePassthrough &&
        (now_ms < flow->delay_window_until_ms || flow->delay_barrier.count > 0 || transcript_pending))
    {
        if (! transcript_pending && now_ms >= flow->delay_window_until_ms && flow->delay_barrier.count > 0)
        {
            ipmanipulatorDelayBarrierTake(&flow->delay_barrier, &release_batch);
            flow->delay_window_until_ms = 0;
            send_current_after_batch    = true;
        }
        else if (ipmanipulatorDelayBarrierTryEnqueue(t,
                                                     kIpManipulatorDelayBarrierOverlapSni,
                                                     &flow->delay_barrier,
                                                     l,
                                                     buf,
                                                     overlapsnitrickHasFinOrRst(&info),
                                                     &needs_schedule))
        {
            barrier_generation = flow->delay_barrier.generation;
            barrier_deadline   = flow->delay_barrier.deadline_ms;
            barrier_owner_wid  = flow->delay_barrier.owner_wid;
        }
        else
        {
            ipmanipulatorDelayBarrierTake(&flow->delay_barrier, &release_batch);
            flow->delay_window_until_ms = 0;
            send_current_after_batch    = true;
        }

        if (send_current_after_batch && overlapsnitrickHasFinOrRst(&info))
        {
            ipmanipulatorFlowShardRemove(&state->overlap_table, shard, entry);
        }

        ipmanipulatorFlowShardUnlock(shard);

        if (needs_schedule)
        {
            uint64_t remaining = barrier_deadline > now_ms ? barrier_deadline - now_ms : 0;
            if (! ipmanipulatorDelayBarrierSchedule(t,
                                                    &key,
                                                    kIpManipulatorDelayBarrierOverlapSni,
                                                    barrier_generation,
                                                    barrier_owner_wid,
                                                    remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining))
            {
                ipmanipulatorDelayBarrierFailOpen(t, &key, kIpManipulatorDelayBarrierOverlapSni, barrier_generation);
            }
        }

        if (! send_current_after_batch)
        {
            return true;
        }

        bool alive = ipmanipulatorDelayBatchSendUpstream(t, &release_batch);
        if (alive && lineIsAlive(l))
        {
            overlapsnitrickSendNormalNow(t, l, buf);
        }
        else
        {
            lineReuseBuffer(l, buf);
        }
        return true;
    }

    if (overlapsnitrickHasFinOrRst(&info))
    {
        if (flow->phase == kIpManipulatorOverlapFlowPhaseHoldThird)
        {
            held_owner_mismatch = ! ipmanipulatorPacketJoinsOwner(flow->held_wid, l);
            bypass_current      = overlapsnitrickTakeHeldPacketLocked(flow, &held_packet);
        }

        ipmanipulatorFlowShardRemove(&state->overlap_table, shard, entry);
        ipmanipulatorFlowShardUnlock(shard);

        if (! bypass_current)
        {
            return false;
        }

        line_t *held_line = held_packet.line;
        if (held_owner_mismatch)
        {
            ipmanipulatorLogCrossWorkerFlowFailure(t,
                                                   "overlap-sni",
                                                   "held packet state",
                                                   lineGetWID(l),
                                                   held_line != NULL ? lineGetWID(held_line) : kInvalidWID);
            if (held_line != NULL && held_packet.buf != NULL)
            {
                ipmanipulatorForwardCapturedPacketNormal(t, held_line, held_packet.buf);
                held_packet.buf = NULL;
            }
            else if (held_packet.buf != NULL)
            {
                sbufDestroy(held_packet.buf);
                held_packet.buf = NULL;
            }
            if (held_line != NULL)
            {
                lineUnref(held_line);
            }
            overlapsnitrickSendNormalNow(t, l, buf);
            return true;
        }
        overlapsnitrickSendHeldThenCurrentNormal(t, &held_packet, l, buf);
        if (held_line != NULL)
        {
            lineUnref(held_line);
        }
        return true;
    }

    switch (flow->phase)
    {
    case kIpManipulatorOverlapFlowPhaseWarmup:
        if (flow->warmup_packets_seen < kOverlapSniWarmupPackets)
        {
            flow->warmup_packets_seen += 1;
            ipmanipulatorFlowShardUnlock(shard);

            overlapsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        if (info.tcp_payload_len == 0)
        {
            flow->phase = kIpManipulatorOverlapFlowPhasePassthrough;
            ipmanipulatorFlowShardUnlock(shard);

            overlapsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        uint32_t                                     tls_record_total_len = 0;
        ipmanipulator_tls_clienthello_start_status_e start_status = ipmanipulatorInspectTlsPayloadClientHelloStart(
            info.packet + info.payload_offset, info.tcp_payload_len, &tls_record_total_len);

        discard tls_record_total_len;

        /*
         * The transcript needs two contiguous payload segments. Anything that
         * is complete already, or is not a ClientHello, cannot be completed by
         * a follow-up segment and must pass without waiting for an RTO.
         */
        if (start_status != kIpManipulatorTlsClientHelloStartPartial &&
            start_status != kIpManipulatorTlsClientHelloStartFragmented)
        {
            flow->phase = kIpManipulatorOverlapFlowPhasePassthrough;
            ipmanipulatorFlowShardUnlock(shard);

            overlapsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        flow->phase            = kIpManipulatorOverlapFlowPhaseHoldThird;
        flow->held_wid         = lineGetWID(l);
        flow->held_packet      = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
        flow->hold_generation  = ipmanipulatorAllocateFlowGeneration(state);
        flow->hold_timer_armed = true;

        uint64_t hold_generation = flow->hold_generation;

        /* The flow record retains the packet line until the hold is detached. */
        lineRef(l);
        ipmanipulatorFlowShardUnlock(shard);

        overlapsnitrickScheduleHoldTimeout(t, l, &key, hold_generation, state->trick_overlap_sni_hold_timeout_ms);
        return true;

    case kIpManipulatorOverlapFlowPhasePassthrough: {
        ipmanipulatorFlowShardUnlock(shard);
        overlapsnitrickSendNormalNow(t, l, buf);
        return true;
    }

    case kIpManipulatorOverlapFlowPhaseHoldThird: {
        overlapsnitrick_handle_result_t result                    = {0};
        bool                            transcript_needs_schedule = false;
        uint64_t                        transcript_generation     = 0;
        uint64_t                        first_action_ms           = 0;

        bool held_worker_mismatch = ! ipmanipulatorPacketJoinsOwner(flow->held_wid, l);

        discard overlapsnitrickTakeHeldPacketLocked(flow, &held_packet);

        if (held_worker_mismatch)
        {
            line_t *held_line = held_packet.line;

            flow->phase = kIpManipulatorOverlapFlowPhasePassthrough;
            ipmanipulatorFlowShardUnlock(shard);

            ipmanipulatorLogCrossWorkerFlowFailure(t,
                                                   "overlap-sni",
                                                   "held packet state",
                                                   lineGetWID(l),
                                                   held_line != NULL ? lineGetWID(held_line) : kInvalidWID);
            if (held_line != NULL && held_packet.buf != NULL)
            {
                ipmanipulatorForwardCapturedPacketNormal(t, held_line, held_packet.buf);
                held_packet.buf = NULL;
            }
            else if (held_packet.buf != NULL)
            {
                sbufDestroy(held_packet.buf);
                held_packet.buf = NULL;
            }
            if (held_line != NULL)
            {
                lineUnref(held_line);
            }
            overlapsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        line_t *held_line = held_packet.line;

        ipmanipulatorFlowShardUnlock(shard);

        bool handled = overlapsnitrickHandleHeldPair(t, l, &held_packet, buf, &info, &result);

        if (held_line != NULL)
        {
            lineUnref(held_line);
        }

        /* The entry pointer did not survive the unlock; resolve the tuple again. */
        shard = ipmanipulatorFlowTableLockShard(&state->overlap_table, &key);
        if (shard != NULL)
        {
            entry = overlapsnitrickFindLocked(state, shard, &key, &info, true);
            if (entry != NULL)
            {
                ipmanipulator_overlap_flow_t *final_flow = overlapsnitrickEntryRecord(entry);

                overlapsnitrickFinalizeFlowLocked(
                    state, final_flow, result.block_flow, &result, now_ms, state->trick_overlap_sni_delay_ms);

                ipmanipulator_ordered_output_t outputs[kOverlapSniMaxEmittedPackets - 2U] = {0};
                uint32_t                       output_count                               = 0;

                for (uint8_t i = 2; i < result.normal_sequence.count; ++i)
                {
                    if (result.normal_sequence.packets[i] == NULL)
                    {
                        continue;
                    }

                    uint64_t due_ms = now_ms + state->trick_overlap_sni_delay_ms +
                                      ((uint64_t) (i - 2U) * kOverlapSniDelaySequenceSpacingMs);
                    outputs[output_count++] = (ipmanipulator_ordered_output_t) {
                        .line   = l,
                        .buf    = result.normal_sequence.packets[i],
                        .send   = overlapsnitrickSendNormalNow,
                        .due_ms = due_ms,
                    };
                }

                if (output_count > 0 && ipmanipulatorDelayBarrierInstallOrdered(t,
                                                                                kIpManipulatorDelayBarrierOverlapSni,
                                                                                &final_flow->delay_barrier,
                                                                                outputs,
                                                                                output_count,
                                                                                &transcript_needs_schedule))
                {
                    first_action_ms = outputs[0].due_ms;
                    for (uint8_t i = 2; i < result.normal_sequence.count; ++i)
                    {
                        result.normal_sequence.packets[i] = NULL;
                    }
                    transcript_generation = final_flow->delay_barrier.generation;
                    transcript_owner_wid  = final_flow->delay_barrier.owner_wid;
                }
                overlapsnitrickTouchLocked(shard, entry, getTickMS());
            }
            ipmanipulatorFlowShardUnlock(shard);
        }

        if (transcript_needs_schedule)
        {
            uint64_t remaining = first_action_ms > now_ms ? first_action_ms - now_ms : 0;
            if (! ipmanipulatorDelayBarrierSchedule(t,
                                                    &key,
                                                    kIpManipulatorDelayBarrierOverlapSni,
                                                    transcript_generation,
                                                    transcript_owner_wid,
                                                    remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining))
            {
                ipmanipulatorDelayBarrierFailOpen(t, &key, kIpManipulatorDelayBarrierOverlapSni, transcript_generation);
            }
        }

        overlapsnitrickSendOutputs(t, l, &result.normal_sequence);

        return handled;
    }

    case kIpManipulatorOverlapFlowPhaseBlocked:
    default:
        ipmanipulatorFlowShardUnlock(shard);
        break;
    }

    return false;
}
