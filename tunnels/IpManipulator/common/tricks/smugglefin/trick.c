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

typedef struct smugglefintrick_handoff_message_s
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t pause_generation;
    uint32_t packet_length;
    uint16_t src_port;
    uint16_t dst_port;
    bool     recalculate_checksum;
    uint8_t  packet[];
} smugglefintrick_handoff_message_t;

#ifdef IPMANIPULATOR_SMUGGLEFIN_TEST_HOOKS
bool ipmanipulatorSmuggleFinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                              WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                              void *arg2, void *arg3);
bool ipmanipulatorSmuggleFinTestScheduleImmediate(wid_t wid, WorkerMessageCallback callback,
                                                  WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                  void *arg3);
#endif

static bool smugglefintrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                              smugglefintrick_tcp_packet_info_t *info)
{
    ipv4_packet_view_t packet_view = {0};
    if (info == NULL || ! ipv4packetviewParseTcp(packet, packet_length, &packet_view) || packet_view.fragmented)
    {
        return false;
    }

    *info = (smugglefintrick_tcp_packet_info_t) {
        .seq             = packet_view.tcp_sequence,
        .ack             = packet_view.tcp_acknowledgment,
        .src_addr        = packet_view.source_address,
        .dst_addr        = packet_view.destination_address,
        .ip_total_len    = packet_view.ip_total_length,
        .ip_header_len   = packet_view.ip_header_length,
        .tcp_header_len  = packet_view.transport_header_length,
        .headers_len     = packet_view.payload_offset,
        .tcp_payload_len = packet_view.payload_length,
        .src_port        = packet_view.source_port,
        .dst_port        = packet_view.destination_port,
        .tcp_flags       = packet_view.tcp_flags,
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

static ipmanipulator_smuggle_fin_flow_t *smugglefintrickEntryRecord(ipmanipulator_flow_entry_t *entry)
{
    return (ipmanipulator_smuggle_fin_flow_t *) ipmanipulatorFlowEntryRecord(entry);
}

static ipmanipulator_flow_key_t smugglefintrickMakeKey(const smugglefintrick_tcp_packet_info_t *info)
{
    return ipmanipulatorFlowKeyMake(info->src_addr, info->src_port, info->dst_addr, info->dst_port);
}

static ipmanipulator_flow_key_t smugglefintrickMakeFlowKey(const ipmanipulator_smuggle_fin_flow_t *flow)
{
    return ipmanipulatorFlowKeyMake(flow->src_addr, flow->src_port, flow->dst_addr, flow->dst_port);
}

/* The record keeps the client-to-server orientation the mirrored FIN is built from. */
static bool smugglefintrickFlowIsForward(const ipmanipulator_smuggle_fin_flow_t  *flow,
                                         const smugglefintrick_tcp_packet_info_t *info)
{
    return flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr && flow->src_port == info->src_port &&
           flow->dst_port == info->dst_port;
}

static bool smugglefintrickFlowIsReverse(const ipmanipulator_smuggle_fin_flow_t  *flow,
                                         const smugglefintrick_tcp_packet_info_t *info)
{
    return flow->src_addr == info->dst_addr && flow->dst_addr == info->src_addr && flow->src_port == info->dst_port &&
           flow->dst_port == info->src_port;
}

static bool smugglefintrickExpectedFinMatches(const ipmanipulator_smuggle_fin_flow_t  *flow,
                                              const smugglefintrick_tcp_packet_info_t *info)
{
    uint32_t flags_without_ecn = (uint32_t) info->tcp_flags & ~(TCP_ECE | TCP_CWR);

    return flow->paused && info->tcp_payload_len == 0 && flags_without_ecn == (TCP_FIN | TCP_ACK) &&
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

static void smugglefintrickInitializeFlow(ipmanipulator_smuggle_fin_flow_t        *flow,
                                          const smugglefintrick_tcp_packet_info_t *info, uint64_t now_ms)
{
    smugglefintrickDestroyFlow(flow);

    *flow = (ipmanipulator_smuggle_fin_flow_t) {
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
    };
}

/* Runs under the shard lock: dispose only, never forward or call the tunnel. */
static void smugglefintrickDestroyFlowRecord(void *record, void *context)
{
    discard context;

    smugglefintrickDestroyFlow((ipmanipulator_smuggle_fin_flow_t *) record);
}

/*
 * A paused flow owns queued buffers on its owner worker and must never be
 * reclaimed by idle expiry; it only leaves the table through a release path or
 * tunnel teardown.
 */
static uint64_t smugglefintrickDeadline(const ipmanipulator_smuggle_fin_flow_t *flow, uint64_t now_ms)
{
    if (flow->paused)
    {
        return UINT64_MAX;
    }

    return now_ms +
           (flow->confirmed ? (uint64_t) kSmuggleFinIdleTimeoutMs : (uint64_t) kSmuggleFinUnconfirmedIdleTimeoutMs);
}

static void smugglefintrickTouchLocked(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                       uint64_t now_ms)
{
    ipmanipulator_smuggle_fin_flow_t *flow = smugglefintrickEntryRecord(entry);

    flow->last_activity_ms = now_ms;
    ipmanipulatorFlowShardTouch(shard, entry, smugglefintrickDeadline(flow, now_ms));
}

static ipmanipulator_smuggle_fin_worker_pause_t *smugglefintrickWorkerRegistry(ipmanipulator_tstate_t *state, wid_t wid)
{
    if (state->smuggle_fin_worker_pauses == NULL || (uint32_t) wid >= state->smuggle_fin_worker_pauses_count)
    {
        return NULL;
    }

    return &state->smuggle_fin_worker_pauses[(uint32_t) wid];
}

/* Only the flow-owner worker installs or clears its own registry slot. */
static void smugglefintrickInstallWorkerRegistry(ipmanipulator_tstate_t *state, wid_t wid,
                                                 const ipmanipulator_flow_key_t *key, uint32_t pause_generation)
{
    ipmanipulator_smuggle_fin_worker_pause_t *registry = smugglefintrickWorkerRegistry(state, wid);

    if (registry != NULL)
    {
        *registry = (ipmanipulator_smuggle_fin_worker_pause_t) {
            .key              = *key,
            .pause_generation = pause_generation,
            .installed        = true,
        };
    }
}

static void smugglefintrickClearWorkerRegistry(ipmanipulator_tstate_t *state, wid_t wid,
                                               const ipmanipulator_flow_key_t *key, uint32_t pause_generation)
{
    ipmanipulator_smuggle_fin_worker_pause_t *registry = smugglefintrickWorkerRegistry(state, wid);

    if (registry != NULL && registry->installed && registry->pause_generation == pause_generation &&
        ipmanipulatorFlowKeyEquals(&registry->key, key))
    {
        registry->installed = false;
    }
}

/*
 * Answers whether this worker already owns a paused flow on some other tuple.
 * Must run with no shard lock held; it takes and releases one shard lock and
 * clears a registry entry that no longer names a live paused flow of its own.
 * A same-tuple registry entry is validated by the caller under the packet lock.
 */
static bool smugglefintrickWorkerOwnsOtherPause(ipmanipulator_tstate_t         *state,
                                                const ipmanipulator_flow_key_t *packet_key, wid_t wid)
{
    ipmanipulator_smuggle_fin_worker_pause_t *registry = smugglefintrickWorkerRegistry(state, wid);

    if (registry == NULL || ! registry->installed || ipmanipulatorFlowKeyEquals(&registry->key, packet_key))
    {
        return false;
    }

    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &registry->key);
    bool                        owns  = false;

    if (shard != NULL)
    {
        ipmanipulator_flow_entry_t *entry =
            ipmanipulatorFlowShardFind(&state->smuggle_fin_table, shard, &registry->key);

        if (entry != NULL)
        {
            const ipmanipulator_smuggle_fin_flow_t *flow = smugglefintrickEntryRecord(entry);

            owns = flow->paused && flow->pause_generation == registry->pause_generation && flow->line != NULL &&
                   lineGetWID(flow->line) == wid;
        }

        ipmanipulatorFlowShardUnlock(shard);
    }

    if (! owns)
    {
        registry->installed = false;
    }

    return owns;
}

static bool smugglefintrickQueuePacketLocked(ipmanipulator_smuggle_fin_flow_t *flow, sbuf_t *buf,
                                             ipmanipulator_smuggle_fin_queue_direction_e direction,
                                             bool                                        recalculate_checksum)
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

    flow->queued_packets[flow->queued_packets_count++] = (ipmanipulator_smuggle_fin_queued_packet_t) {
        .buf                  = buf,
        .direction            = direction,
        .recalculate_checksum = recalculate_checksum,
    };
    return true;
}

/*
 * Detaches the queued batch and unpauses the flow. Every caller runs on the
 * flow-owner worker, so the worker registry is cleared here too and the entry
 * goes back to a normal idle deadline.
 */
static void smugglefintrickDetachQueuedPacketsLocked(ipmanipulator_tstate_t *state, ipmanipulator_flow_shard_t *shard,
                                                     ipmanipulator_flow_entry_t *entry, bool force, uint64_t now_ms,
                                                     ipmanipulator_smuggle_fin_queued_packet_t **queued_packets,
                                                     uint32_t                                   *queued_packets_count)
{
    ipmanipulator_smuggle_fin_flow_t *flow  = smugglefintrickEntryRecord(entry);
    wid_t                             owner = flow->line != NULL ? lineGetWID(flow->line) : getCurrentEventWorkerWID();
    ipmanipulator_flow_key_t          flow_key = smugglefintrickMakeFlowKey(flow);

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

    smugglefintrickClearWorkerRegistry(state, owner, &flow_key, flow->pause_generation);
    ipmanipulatorFlowShardTouch(shard, entry, smugglefintrickDeadline(flow, now_ms));
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

        lineSetRecalculateChecksum(l, entry->recalculate_checksum);

        if (entry->direction == kIpManipulatorSmuggleFinQueueDirectionUpstream)
        {
            ipmanipulatorUpStreamPayload(t, l, entry->buf);
        }
        else
        {
            ipmanipulatorDownStreamPayloadAfterSmuggleFin(t, l, entry->buf);
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
    if (UNLIKELY(context == NULL))
    {
        LOGF("IpManipulator: failed to allocate a smuggle-fin release context");
        abortProgramNow(1);
    }

    *context = (smugglefintrick_release_context_t) {
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

    assert(lineIsOnCurrentEventWorker(l));

    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(context->src_addr, context->src_port, context->dst_addr, context->dst_port);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &key);

    if (shard == NULL)
    {
        return;
    }

    ipmanipulator_flow_entry_t       *entry = ipmanipulatorFlowShardFind(&state->smuggle_fin_table, shard, &key);
    ipmanipulator_smuggle_fin_flow_t *flow  = entry != NULL ? smugglefintrickEntryRecord(entry) : NULL;

    if (flow == NULL || flow->src_addr != context->src_addr || flow->src_port != context->src_port || ! flow->paused ||
        flow->pause_generation != context->generation || (! context->force && ! flow->release_pending))
    {
        ipmanipulatorFlowShardUnlock(shard);
        return;
    }

    if (context->force)
    {
        LOGW("IpManipulator: smuggle-fin pause timed out after %u ms; releasing the flow",
             state->trick_smuggle_fin_pause_timeout_ms);
    }

    smugglefintrickDetachQueuedPacketsLocked(
        state, shard, entry, context->force, now_ms, &queued_packets, &queued_packets_count);

    ipmanipulatorFlowShardUnlock(shard);

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

static void smugglefintrickCleanupDelayedRelease(void *arg1, void *arg2, void *arg3,
                                                 worker_message_cancel_reason_e reason)
{
    discard                            reason;
    tunnel_t                          *t       = arg1;
    line_t                            *l       = arg2;
    smugglefintrick_release_context_t *context = arg3;

    if (lineIsOnCurrentEventWorker(l) && lineIsAlive(l))
    {
        context->force = true;
        smugglefintrickReleaseQueuedPacketsNow(t, l, context);
    }
    memoryFree(context);
    lineUnlock(l);
}

static bool smugglefintrickScheduleQueuedRelease(tunnel_t *t, line_t *l, uint32_t delay_ms,
                                                 smugglefintrick_release_context_t *context)
{
    if (delay_ms == 0 && lineIsOnCurrentEventWorker(l))
    {
        smugglefintrickReleaseQueuedPacketsNow(t, l, context);
        memoryFree(context);
        return true;
    }

    smugglefintrick_release_context_t recovery_context = *context;
    recovery_context.force                             = true;
    const bool recover_on_caller                       = lineIsOnCurrentEventWorker(l) && lineIsAlive(l);

    lineLock(l);
    WW_WORKER_MESSAGE_BENCHMARK_RECORD_CONTINUATION(kWorkerMessageBenchmarkContinuationIpManipulatorDeferred);
#ifdef IPMANIPULATOR_SMUGGLEFIN_TEST_HOOKS
    bool scheduled = ipmanipulatorSmuggleFinTestScheduleTimed(lineGetWID(l),
                                                              (WorkerMessageCallback) smugglefintrickRunDelayedRelease,
                                                              smugglefintrickCleanupDelayedRelease,
                                                              delay_ms,
                                                              t,
                                                              l,
                                                              context);
#else
    bool scheduled = sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                                       (WorkerMessageCallback) smugglefintrickRunDelayedRelease,
                                                       smugglefintrickCleanupDelayedRelease,
                                                       delay_ms,
                                                       t,
                                                       l,
                                                       context) == kWorkerMessageSubmitAccepted;
#endif
    if (! scheduled && recover_on_caller)
    {
        smugglefintrickReleaseQueuedPacketsNow(t, l, &recovery_context);
    }
    return scheduled;
}

static void smugglefintrickForceReleaseAfterQueueLimit(tunnel_t *t, line_t *l,
                                                       ipmanipulator_smuggle_fin_queued_packet_t *queued_packets,
                                                       uint32_t queued_packets_count, bool current_recalculate_checksum)
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

    if (! lineIsAlive(l))
    {
        LOGF("IpManipulator: worker packet line died while releasing a full smuggle-fin queue");
        abortProgramNow(1);
    }

    lineSetRecalculateChecksum(l, current_recalculate_checksum);
}

static sbuf_t *smugglefintrickCreateHandoffBuffer(line_t *owner_line, uint32_t packet_length)
{
    buffer_pool_t *pool = lineGetBufferPool(owner_line);
    sbuf_t        *buf  = NULL;

    if (packet_length <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (packet_length <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        buf = sbufCreateWithPadding(packet_length, bufferpoolGetLargeBufferPadding(pool));
    }

    if (buf != NULL)
    {
        sbufSetLength(buf, packet_length);
    }

    return buf;
}

static void smugglefintrickCleanupHandoffMessage(void *arg1, void *arg2, void *arg3,
                                                 worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;

    memoryFree(arg3);
    lineUnlock((line_t *) arg2);
}

static void smugglefintrickRunHandoffMessage(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    tunnel_t                                  *t                    = arg1;
    line_t                                    *owner_line           = arg2;
    smugglefintrick_handoff_message_t         *message              = arg3;
    ipmanipulator_tstate_t                    *state                = tunnelGetState(t);
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets       = NULL;
    uint32_t                                   queued_packets_count = 0;

    assert(worker != NULL);
    assert(currentThreadIsEventWorkerWID(worker->wid));
    assert(lineGetWID(owner_line) == worker->wid);
    discard worker;

    if (! lineIsAlive(owner_line))
    {
        memoryFree(message);
        lineUnlock(owner_line);
        LOGF("IpManipulator: worker packet line died before a smuggle-fin handoff ran");
        abortProgramNow(1);
    }

    uint32_t                          src_addr             = message->src_addr;
    uint32_t                          dst_addr             = message->dst_addr;
    uint32_t                          pause_generation     = message->pause_generation;
    uint32_t                          packet_length        = message->packet_length;
    uint16_t                          src_port             = message->src_port;
    uint16_t                          dst_port             = message->dst_port;
    bool                              recalculate_checksum = message->recalculate_checksum;
    sbuf_t                           *buf      = smugglefintrickCreateHandoffBuffer(owner_line, packet_length);
    smugglefintrick_release_context_t flow_key = {
        .src_addr   = src_addr,
        .dst_addr   = dst_addr,
        .generation = pause_generation,
        .src_port   = src_port,
        .dst_port   = dst_port,
    };

    if (buf == NULL)
    {
        memoryFree(message);
        lineUnlock(owner_line);
        LOGF("IpManipulator: failed to allocate an owner-worker buffer for a smuggle-fin handoff");
        abortProgramNow(1);
    }

    memoryCopyLarge(sbufGetMutablePtr(buf), message->packet, packet_length);
    memoryFree(message);

    ipmanipulator_flow_key_t    key   = ipmanipulatorFlowKeyMake(src_addr, src_port, dst_addr, dst_port);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &key);
    ipmanipulator_flow_entry_t *entry =
        shard != NULL ? ipmanipulatorFlowShardFind(&state->smuggle_fin_table, shard, &key) : NULL;
    ipmanipulator_smuggle_fin_flow_t *flow = entry != NULL ? smugglefintrickEntryRecord(entry) : NULL;

    discard flow_key;

    if (flow != NULL && flow->src_addr == src_addr && flow->src_port == src_port && flow->paused &&
        flow->pause_generation == pause_generation && flow->line == owner_line)
    {
        smugglefintrickTouchLocked(shard, entry, getTickMS());

        if (smugglefintrickQueuePacketLocked(
                flow, buf, kIpManipulatorSmuggleFinQueueDirectionDownstream, recalculate_checksum))
        {
            lineSetRecalculateChecksum(owner_line, false);
            ipmanipulatorFlowShardUnlock(shard);
            lineUnlock(owner_line);
            return;
        }

        smugglefintrickDetachQueuedPacketsLocked(
            state, shard, entry, true, getTickMS(), &queued_packets, &queued_packets_count);
        ipmanipulatorFlowShardUnlock(shard);

        smugglefintrickForceReleaseAfterQueueLimit(
            t, owner_line, queued_packets, queued_packets_count, recalculate_checksum);
    }
    else
    {
        ipmanipulatorFlowShardUnlock(shard);
        lineSetRecalculateChecksum(owner_line, recalculate_checksum);
    }

    ipmanipulatorDownStreamPayloadAfterSmuggleFin(t, owner_line, buf);

    if (! lineIsAlive(owner_line))
    {
        lineUnlock(owner_line);
        LOGF("IpManipulator: worker packet line died while resuming a smuggle-fin handoff");
        abortProgramNow(1);
    }

    lineUnlock(owner_line);
}

bool smugglefintrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));

    ipmanipulator_tstate_t                    *state                = tunnelGetState(t);
    smugglefintrick_tcp_packet_info_t          info                 = {0};
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets       = NULL;
    uint32_t                                   queued_packets_count = 0;
    uint64_t                                   now_ms               = getTickMS();

    assert(state->trick_real_fin_upstream_tunnel != NULL);

    /*
     * A pause belongs to one parseable TCP flow. Unparseable packets and every
     * unrelated flow continue normally instead of being held behind it.
     */
    if (! smugglefintrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    bool current_recalculate_checksum = lineGetRecalculateChecksum(l);

    ipmanipulator_flow_key_t key = smugglefintrickMakeKey(&info);

    /*
     * Resolved before the packet shard is locked so the two shard locks are
     * never nested. A stale registry entry is cleared by this call.
     */
    bool worker_has_paused_flow = smugglefintrickWorkerOwnsOtherPause(state, &key, lineGetWID(l));

    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &key);

    if (shard == NULL)
    {
        return false;
    }

    discard ipmanipulatorFlowShardExpire(&state->smuggle_fin_table, shard, now_ms, kIpManipulatorFlowCleanupBudget);

    ipmanipulator_flow_entry_t       *entry = ipmanipulatorFlowShardFind(&state->smuggle_fin_table, shard, &key);
    ipmanipulator_smuggle_fin_flow_t *flow  = entry != NULL ? smugglefintrickEntryRecord(entry) : NULL;

    if (flow != NULL && ! smugglefintrickFlowIsForward(flow, &info))
    {
        if (! smugglefintrickShouldMirror(&info))
        {
            entry = NULL;
            flow  = NULL;
        }
        else
        {
            /*
             * The normalized tuple already belongs to the reverse orientation.
             * Cancel its pause/queue ownership before reusing the sole canonical
             * entry for the new transcript.
             */
            if (flow->paused && flow->line != NULL && lineIsOnCurrentEventWorker(flow->line))
            {
                ipmanipulator_flow_key_t old_key = smugglefintrickMakeFlowKey(flow);

                smugglefintrickClearWorkerRegistry(state, lineGetWID(flow->line), &old_key, flow->pause_generation);
            }

            smugglefintrickInitializeFlow(flow, &info, now_ms);
        }
    }

    if (flow != NULL)
    {
        smugglefintrickTouchLocked(shard, entry, now_ms);

        if (flow->paused)
        {
            if (smugglefintrickQueuePacketLocked(
                    flow, buf, kIpManipulatorSmuggleFinQueueDirectionUpstream, current_recalculate_checksum))
            {
                lineSetRecalculateChecksum(l, false);
                ipmanipulatorFlowShardUnlock(shard);
                return true;
            }

            smugglefintrickDetachQueuedPacketsLocked(
                state, shard, entry, true, now_ms, &queued_packets, &queued_packets_count);
            ipmanipulatorFlowShardUnlock(shard);
            smugglefintrickForceReleaseAfterQueueLimit(
                t, l, queued_packets, queued_packets_count, current_recalculate_checksum);
            return false;
        }

        if (flow->confirmed)
        {
            ipmanipulatorFlowShardUnlock(shard);
            return false;
        }
    }

    if ((flow == NULL && worker_has_paused_flow) || ! smugglefintrickShouldMirror(&info))
    {
        ipmanipulatorFlowShardUnlock(shard);
        return false;
    }

    sbuf_t *fin_packet = smugglefintrickBuildMirrorFinPacket(l, buf, &info);
    if (fin_packet == NULL)
    {
        ipmanipulatorFlowShardUnlock(shard);
        return false;
    }

    if (entry == NULL)
    {
        entry = ipmanipulatorFlowShardReserve(
            &state->smuggle_fin_table, shard, &key, now_ms, now_ms + kSmuggleFinUnconfirmedIdleTimeoutMs);

        if (entry != NULL)
        {
            smugglefintrickInitializeFlow(smugglefintrickEntryRecord(entry), &info, now_ms);
        }

        flow = entry != NULL ? smugglefintrickEntryRecord(entry) : NULL;
    }

    if (flow == NULL)
    {
        ipmanipulatorFlowShardUnlock(shard);
        lineReuseBuffer(l, fin_packet);
        LOGW("IpManipulator: smuggle-fin could not admit a connection record; the packet passes unchanged");
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
     * Allocate generations across the whole tunnel so reusing a tuple cannot let
     * an old delayed-release context match a new occupant.
     */
    uint32_t pause_generation = (uint32_t) atomicInc(&state->smuggle_fin_next_pause_generation) + 1U;
    if (pause_generation == 0)
    {
        pause_generation = (uint32_t) atomicInc(&state->smuggle_fin_next_pause_generation) + 1U;
    }
    flow->pause_generation = pause_generation;

    ipmanipulatorFlowShardTouch(shard, entry, smugglefintrickDeadline(flow, now_ms));

    if (! smugglefintrickQueuePacketLocked(
            flow, buf, kIpManipulatorSmuggleFinQueueDirectionUpstream, current_recalculate_checksum))
    {
        smugglefintrickDetachQueuedPacketsLocked(
            state, shard, entry, true, now_ms, &queued_packets, &queued_packets_count);
        ipmanipulatorFlowShardUnlock(shard);
        lineReuseBuffer(l, fin_packet);
        smugglefintrickForceReleaseAfterQueueLimit(
            t, l, queued_packets, queued_packets_count, current_recalculate_checksum);
        return false;
    }

    lineSetRecalculateChecksum(l, false);

    smugglefintrickInstallWorkerRegistry(state, lineGetWID(l), &key, pause_generation);

    smugglefintrick_release_context_t *timeout_context = smugglefintrickCreateReleaseContextLocked(flow, true);

    ipmanipulatorFlowShardUnlock(shard);

    smugglefintrickScheduleQueuedRelease(t, l, state->trick_smuggle_fin_pause_timeout_ms, timeout_context);

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

    lineSetRecalculateChecksum(l, false);
    lineUnlock(l);

    LOGD("IpManipulator: smuggle-fin sent a mirrored FIN packet to \"%s\" and paused flow generation %u",
         state->trick_real_fin_upstream_node != NULL ? state->trick_real_fin_upstream_node->name : "(null)",
         pause_generation);

    return true;
}

bool smugglefintrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));

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

    bool current_recalculate_checksum = lineGetRecalculateChecksum(l);

    ipmanipulator_flow_key_t    key   = smugglefintrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &key);

    if (shard == NULL)
    {
        return false;
    }

    discard ipmanipulatorFlowShardExpire(&state->smuggle_fin_table, shard, now_ms, kIpManipulatorFlowCleanupBudget);

    /*
     * Both the mirrored-FIN echo and ordinary reverse traffic normalize to the
     * same key, so one lookup replaces the old expected/reverse table scans.
     */
    ipmanipulator_flow_entry_t       *entry = ipmanipulatorFlowShardFind(&state->smuggle_fin_table, shard, &key);
    ipmanipulator_smuggle_fin_flow_t *flow  = entry != NULL ? smugglefintrickEntryRecord(entry) : NULL;

    if (flow != NULL && ! smugglefintrickFlowIsReverse(flow, &info))
    {
        entry = NULL;
        flow  = NULL;
    }

    if (flow != NULL && smugglefintrickExpectedFinMatches(flow, &info))
    {
        smugglefintrickTouchLocked(shard, entry, now_ms);

        if (flow->release_pending)
        {
            ipmanipulatorFlowShardUnlock(shard);
            lineSetRecalculateChecksum(l, false);
            lineReuseBuffer(l, buf);
            return true;
        }

        flow->confirmed       = true;
        flow->release_pending = true;

        line_t                            *owner_line       = flow->line;
        smugglefintrick_release_context_t *release_context  = smugglefintrickCreateReleaseContextLocked(flow, false);
        uint32_t                           release_delay_ms = state->trick_smuggle_fin_delay_ms;

        ipmanipulatorFlowShardUnlock(shard);

        lineSetRecalculateChecksum(l, false);
        lineReuseBuffer(l, buf);

        LOGD("IpManipulator: received the expected smuggle-fin echo and will release its flow after %u ms",
             release_delay_ms);
        smugglefintrickScheduleQueuedRelease(t, owner_line, release_delay_ms, release_context);
        return true;
    }

    if (flow != NULL)
    {
        if (flow->paused)
        {
            line_t *owner_line = flow->line;
            if (owner_line == NULL)
            {
                ipmanipulatorFlowShardUnlock(shard);
                return false;
            }

            if (lineGetWID(owner_line) != lineGetWID(l))
            {
                uint32_t packet_length = sbufGetLength(buf);
                wid_t    owner_wid     = lineGetWID(owner_line);

                lineLock(owner_line);

                uint32_t src_addr         = flow->src_addr;
                uint32_t dst_addr         = flow->dst_addr;
                uint32_t pause_generation = flow->pause_generation;
                uint16_t src_port         = flow->src_port;
                uint16_t dst_port         = flow->dst_port;

                ipmanipulatorFlowShardUnlock(shard);

#if WW_COMPILE_FOR_32BIT
                if (packet_length > (uint32_t) (SIZE_MAX - sizeof(smugglefintrick_handoff_message_t)))
                {
                    lineUnlock(owner_line);
                    return false;
                }
#endif

                smugglefintrick_handoff_message_t *message = memoryAllocate(sizeof(*message) + (size_t) packet_length);
                if (message == NULL)
                {
                    lineUnlock(owner_line);
                    return false;
                }

                *message = (smugglefintrick_handoff_message_t) {
                    .src_addr             = src_addr,
                    .dst_addr             = dst_addr,
                    .pause_generation     = pause_generation,
                    .packet_length        = packet_length,
                    .src_port             = src_port,
                    .dst_port             = dst_port,
                    .recalculate_checksum = current_recalculate_checksum,
                };
                memoryCopyLarge(message->packet, sbufGetRawPtr(buf), packet_length);

#ifdef IPMANIPULATOR_SMUGGLEFIN_TEST_HOOKS
                bool submitted = ipmanipulatorSmuggleFinTestScheduleImmediate(
                    owner_wid,
                    (WorkerMessageCallback) smugglefintrickRunHandoffMessage,
                    smugglefintrickCleanupHandoffMessage,
                    t,
                    owner_line,
                    message);
#else
                bool submitted =
                    sendWorkerMessageForceQueueWithCleanup(owner_wid,
                                                           (WorkerMessageCallback) smugglefintrickRunHandoffMessage,
                                                           smugglefintrickCleanupHandoffMessage,
                                                           t,
                                                           owner_line,
                                                           message) == kWorkerMessageSubmitAccepted;
#endif
                if (! submitted)
                {
                    return false;
                }

                lineSetRecalculateChecksum(l, false);
                lineReuseBuffer(l, buf);
                return true;
            }

            smugglefintrickTouchLocked(shard, entry, now_ms);

            if (smugglefintrickQueuePacketLocked(
                    flow, buf, kIpManipulatorSmuggleFinQueueDirectionDownstream, current_recalculate_checksum))
            {
                lineSetRecalculateChecksum(l, false);
                ipmanipulatorFlowShardUnlock(shard);
                return true;
            }

            smugglefintrickDetachQueuedPacketsLocked(
                state, shard, entry, true, now_ms, &queued_packets, &queued_packets_count);
            ipmanipulatorFlowShardUnlock(shard);
            smugglefintrickForceReleaseAfterQueueLimit(
                t, owner_line, queued_packets, queued_packets_count, current_recalculate_checksum);
            return false;
        }

        smugglefintrickTouchLocked(shard, entry, now_ms);
    }

    ipmanipulatorFlowShardUnlock(shard);
    return false;
}

bool smugglefintrickInitializeState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    state->smuggle_fin_worker_pauses_count = (uint32_t) getTotalWorkersCount();
    state->smuggle_fin_worker_pauses =
        memoryAllocateZero(sizeof(*state->smuggle_fin_worker_pauses) * state->smuggle_fin_worker_pauses_count);

    if (state->smuggle_fin_worker_pauses == NULL)
    {
        state->smuggle_fin_worker_pauses_count = 0;
        LOGF("IpManipulator: failed to allocate the smuggle-fin per-worker paused-flow registry");
        return false;
    }

    return ipmanipulatorFlowTableInit(&state->smuggle_fin_table,
                                      "smuggle-fin",
                                      state->trick_stateful_flow_limit,
                                      (uint32_t) getTotalWorkersCount(),
                                      sizeof(ipmanipulator_smuggle_fin_flow_t),
                                      smugglefintrickDestroyFlowRecord,
                                      NULL);
}

void smugglefintrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    ipmanipulatorFlowTableDestroy(&state->smuggle_fin_table);

    memoryFree(state->smuggle_fin_worker_pauses);
    state->smuggle_fin_worker_pauses       = NULL;
    state->smuggle_fin_worker_pauses_count = 0;
}
