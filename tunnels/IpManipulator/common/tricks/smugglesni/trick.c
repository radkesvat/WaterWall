#include "trick.h"

#include "TlsClient/interface.h"
#include "loggers/network_logger.h"

enum
{
    kSmuggleSniWarmupPackets = 2,
    kSmuggleSniDelayWindowMs = 50000,
    kSmuggleSniIdleTimeoutMs = 20U * 60U * 1000U
};

typedef struct smugglesnitrick_tcp_packet_info_s
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t seq;
    uint32_t payload_offset;
    uint8_t  tcp_flags;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t ip_total_len;
    uint16_t tcp_payload_len;
} smugglesnitrick_tcp_packet_info_t;

typedef enum smugglesnitrick_action_e
{
    kSmuggleSniActionPassNormal = 0,
    kSmuggleSniActionCapture
} smugglesnitrick_action_e;

typedef struct smugglesnitrick_fake_batch_entry_s
{
    line_t *line;
    sbuf_t *buf;
} smugglesnitrick_fake_batch_entry_t;

typedef struct smugglesnitrick_fake_batch_s
{
    uint8_t                            count;
    smugglesnitrick_fake_batch_entry_t entries[kIpManipulatorTlsCaptureMaxPackets];
} smugglesnitrick_fake_batch_t;

static bool smugglesnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                              smugglesnitrick_tcp_packet_info_t *info)
{
    ipv4_packet_view_t packet_view = {0};
    if (info == NULL || ! ipv4packetviewParseTcp(packet, packet_length, &packet_view) || packet_view.fragmented)
    {
        return false;
    }

    *info = (smugglesnitrick_tcp_packet_info_t) {
        .src_addr        = packet_view.source_address,
        .dst_addr        = packet_view.destination_address,
        .seq             = packet_view.tcp_sequence,
        .payload_offset  = packet_view.payload_offset,
        .tcp_flags       = packet_view.tcp_flags,
        .src_port        = packet_view.source_port,
        .dst_port        = packet_view.destination_port,
        .ip_total_len    = packet_view.ip_total_length,
        .tcp_payload_len = packet_view.payload_length,
    };

    return true;
}

static bool smugglesnitrickIsPureSyn(const smugglesnitrick_tcp_packet_info_t *info)
{
    return ipmanipulatorIsFlowOpeningSyn(info->tcp_flags, info->tcp_payload_len);
}

static bool smugglesnitrickHasFinOrRst(const smugglesnitrick_tcp_packet_info_t *info)
{
    return (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static ipmanipulator_flow_key_t smugglesnitrickMakeKey(const smugglesnitrick_tcp_packet_info_t *info)
{
    return ipmanipulatorFlowKeyMake(info->src_addr, info->src_port, info->dst_addr, info->dst_port);
}

static ipmanipulator_smuggle_flow_t *smugglesnitrickEntryRecord(ipmanipulator_flow_entry_t *entry)
{
    return (ipmanipulator_smuggle_flow_t *) ipmanipulatorFlowEntryRecord(entry);
}

/* The record keeps the client-to-server orientation the transcript logic uses. */
static bool smugglesnitrickFlowIsForward(const ipmanipulator_smuggle_flow_t      *flow,
                                         const smugglesnitrick_tcp_packet_info_t *info)
{
    return flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr && flow->src_port == info->src_port &&
           flow->dst_port == info->dst_port;
}

static ipmanipulator_flow_shard_t *smugglesnitrickLockShard(ipmanipulator_tstate_t         *state,
                                                            const ipmanipulator_flow_key_t *key, uint64_t now_ms)
{
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_table, key);

    if (shard != NULL)
    {
        discard ipmanipulatorFlowShardExpire(&state->smuggle_table, shard, now_ms, kIpManipulatorFlowCleanupBudget);
    }

    return shard;
}

static void smugglesnitrickTouchLocked(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                       uint64_t now_ms)
{
    smugglesnitrickEntryRecord(entry)->last_activity_ms = now_ms;
    ipmanipulatorFlowShardTouch(shard, entry, now_ms + kSmuggleSniIdleTimeoutMs);
}

/*
 * Finds the entry for this tuple and, when require_forward is set, rejects a
 * record whose stored orientation does not match the packet direction.
 */
static ipmanipulator_flow_entry_t *smugglesnitrickFindLocked(ipmanipulator_tstate_t                  *state,
                                                             ipmanipulator_flow_shard_t              *shard,
                                                             const ipmanipulator_flow_key_t          *key,
                                                             const smugglesnitrick_tcp_packet_info_t *info,
                                                             bool                                     require_forward)
{
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->smuggle_table, shard, key);

    if (entry != NULL && require_forward && ! smugglesnitrickFlowIsForward(smugglesnitrickEntryRecord(entry), info))
    {
        return NULL;
    }

    return entry;
}

static void smugglesnitrickInitializeFlow(ipmanipulator_smuggle_flow_t            *flow,
                                          const smugglesnitrick_tcp_packet_info_t *info, uint64_t now_ms)
{
    ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
    uint64_t barrier_generation = flow->delay_barrier.generation;

    *flow = (ipmanipulator_smuggle_flow_t) {
        .created_ms       = now_ms,
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .phase            = kIpManipulatorSmuggleFlowPhaseWarmup,
    };
    flow->delay_barrier.generation = barrier_generation;
}

static ipmanipulator_flow_entry_t *smugglesnitrickReserveLocked(ipmanipulator_tstate_t                  *state,
                                                                ipmanipulator_flow_shard_t              *shard,
                                                                const ipmanipulator_flow_key_t          *key,
                                                                const smugglesnitrick_tcp_packet_info_t *info,
                                                                uint64_t                                 now_ms)
{
    ipmanipulator_flow_entry_t *entry =
        ipmanipulatorFlowShardReserve(&state->smuggle_table, shard, key, now_ms, now_ms + kSmuggleSniIdleTimeoutMs);

    if (entry == NULL)
    {
        return NULL;
    }

    smugglesnitrickInitializeFlow(smugglesnitrickEntryRecord(entry), info, now_ms);

    return entry;
}

/* Marks the flow for this tuple as passthrough regardless of packet direction. */
static void smugglesnitrickMarkPassthrough(ipmanipulator_tstate_t *state, const ipmanipulator_flow_key_t *key,
                                           uint64_t delay_window_until_ms)
{
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_table, key);

    if (shard == NULL)
    {
        return;
    }

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->smuggle_table, shard, key);
    if (entry != NULL)
    {
        ipmanipulator_smuggle_flow_t *flow = smugglesnitrickEntryRecord(entry);

        flow->phase                 = kIpManipulatorSmuggleFlowPhasePassthrough;
        flow->delay_window_until_ms = delay_window_until_ms;
        ipmanipulatorDelayBarrierInitialize(state, &flow->delay_barrier, delay_window_until_ms);
    }

    ipmanipulatorFlowShardUnlock(shard);
}

static void smugglesnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    lineSetRecalculateChecksum(l, true);
    ipmanipulatorEmitUpstream(t, l, buf, tunnelNextUpStreamPayload);
}

static void smugglesnitrickSendFakeBatchNow(tunnel_t *t, smugglesnitrick_fake_batch_t *batch)
{
    if (batch == NULL)
    {
        return;
    }

    for (uint8_t i = 0; i < batch->count; ++i)
    {
        smugglesnitrick_fake_batch_entry_t *entry = &batch->entries[i];

        if (entry->line != NULL && entry->buf != NULL)
        {
            if (lineIsAlive(entry->line))
            {
                smugglesnitrickSendNormalNow(t, entry->line, entry->buf);
            }
            else
            {
                lineReuseBuffer(entry->line, entry->buf);
            }
            entry->line = NULL;
            entry->buf  = NULL;
        }
    }
}

static void smugglesnitrickStartOrderedFakeBatch(tunnel_t *t, const ipmanipulator_flow_key_t *key,
                                                 smugglesnitrick_fake_batch_t *batch, uint64_t now_ms)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (batch == NULL || batch->count == 0)
    {
        memoryFree(batch);
        smugglesnitrickMarkPassthrough(state, key, 0);
        return;
    }

    if (state->trick_smuggle_sni_delay_ms == 0)
    {
        smugglesnitrickSendFakeBatchNow(t, batch);
        memoryFree(batch);
        smugglesnitrickMarkPassthrough(state, key, now_ms + kSmuggleSniDelayWindowMs);
        return;
    }

    uint64_t                       due_ms            = now_ms + state->trick_smuggle_sni_delay_ms;
    uint64_t                       minimum_window_ms = (uint64_t) state->trick_smuggle_sni_delay_ms + 1U;
    uint64_t                       deadline_ms = now_ms + max((uint64_t) kSmuggleSniDelayWindowMs, minimum_window_ms);
    ipmanipulator_ordered_output_t outputs[kIpManipulatorTlsCaptureMaxPackets] = {0};

    for (uint8_t i = 0; i < batch->count; ++i)
    {
        outputs[i] = (ipmanipulator_ordered_output_t) {
            .line   = batch->entries[i].line,
            .buf    = batch->entries[i].buf,
            .send   = smugglesnitrickSendNormalNow,
            .due_ms = due_ms,
        };
    }

    bool     installed      = false;
    bool     needs_schedule = false;
    uint64_t generation     = 0;
    wid_t    wid            = lineGetWID(batch->entries[0].line);

    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_table, key);
    if (shard != NULL)
    {
        ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->smuggle_table, shard, key);
        if (entry != NULL)
        {
            ipmanipulator_smuggle_flow_t *flow = smugglesnitrickEntryRecord(entry);

            flow->phase                 = kIpManipulatorSmuggleFlowPhasePassthrough;
            flow->delay_window_until_ms = deadline_ms;
            ipmanipulatorDelayBarrierInitialize(state, &flow->delay_barrier, deadline_ms);
            installed =
                ipmanipulatorDelayBarrierInstallOrdered(&flow->delay_barrier, outputs, batch->count, &needs_schedule);
            generation = flow->delay_barrier.generation;

            if (! installed)
            {
                flow->delay_window_until_ms = 0;
                ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
            }
        }
        ipmanipulatorFlowShardUnlock(shard);
    }

    if (installed)
    {
        for (uint8_t i = 0; i < batch->count; ++i)
        {
            batch->entries[i].line = NULL;
            batch->entries[i].buf  = NULL;
        }

        if (needs_schedule)
        {
            uint64_t remaining = due_ms > now_ms ? due_ms - now_ms : 0;
            ipmanipulatorDelayBarrierSchedule(t,
                                              key,
                                              kIpManipulatorDelayBarrierSmuggleSni,
                                              generation,
                                              wid,
                                              remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining);
        }
    }
    else
    {
        smugglesnitrickSendFakeBatchNow(t, batch);
        smugglesnitrickMarkPassthrough(state, key, 0);
    }

    memoryFree(batch);
}

static void smugglesnitrickForwardReal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    tunnelUpStreamPayload(state->trick_real_sni_upstream_tunnel, l, buf);
}

static void smugglesnitrickSendRealNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    lineSetRecalculateChecksum(l, true);
    ipmanipulatorEmitUpstreamPreservingTuple(t, l, buf, smugglesnitrickForwardReal);
}

static void smugglesnitrickCleanupDelayedBuffer(line_t *l, sbuf_t *buf)
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

sbuf_t *smugglesnitrickGenerateTlsClientHello(tunnel_t *t, line_t *l)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    return tlsclientTunnelGenerateClientHello(state->trick_real_sni_tls_client_tunnel,
                                              l,
                                              (const uint8_t *) state->trick_smuggle_sni_value,
                                              state->trick_smuggle_sni_value_len);
}

static bool smugglesnitrickBuildFakeBatch(tunnel_t *t, line_t *l, ipmanipulator_tls_capture_slot_t *slot,
                                          smugglesnitrick_fake_batch_t *batch)
{
    memoryZero(batch, sizeof(*batch));

    if (slot == NULL || slot->captured_packets_count == 0 || slot->tls_record_total_len == 0)
    {
        return false;
    }

    if (slot->tls_record_total_len > slot->captured_payload_len)
    {
        return false;
    }

    sbuf_t *tls_hello = smugglesnitrickGenerateTlsClientHello(t, l);
    if (tls_hello == NULL)
    {
        LOGD("IpManipulator: smuggle-sni failed to generate TLS ClientHello");
        return false;
    }

    uint32_t generated_len = sbufGetLength(tls_hello);
    if (generated_len != slot->tls_record_total_len)
    {
        LOGD("IpManipulator: smuggle-sni generated TLS ClientHello length mismatch (original=%u, generated=%u); "
             "failing open",
             slot->tls_record_total_len,
             generated_len);
        reuseBuffer(tls_hello);
        return false;
    }

    const uint8_t *generated_bytes = (const uint8_t *) sbufGetRawPtr(tls_hello);

    sni_match_t fake_match = {0};
    if (! parseTlsRecordSni(generated_bytes, generated_len, &fake_match))
    {
        LOGD("IpManipulator: smuggle-sni generated payload is not a valid ClientHello or lacks SNI; failing open");
        reuseBuffer(tls_hello);
        return false;
    }

    if (5U + (uint32_t) fake_match.tls_record_len != generated_len)
    {
        LOGD("IpManipulator: smuggle-sni generated payload contains bytes outside the declared TLS record; failing "
             "open");
        reuseBuffer(tls_hello);
        return false;
    }

    ipmanipulator_tstate_t *state        = tunnelGetState(t);
    uint16_t                fake_sni_len = state->trick_smuggle_sni_value_len;
    if (fake_match.sni_name_len != fake_sni_len ||
        memcmp(generated_bytes + fake_match.sni_name_offset, state->trick_smuggle_sni_value, fake_sni_len) != 0)
    {
        LOGD("IpManipulator: smuggle-sni generated SNI does not match configured fake SNI; failing open");
        reuseBuffer(tls_hello);
        return false;
    }

    uint32_t tls_record_len = slot->tls_record_total_len;
    uint32_t stream_offset  = 0;
    uint32_t first_seq      = 0;

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        ipmanipulator_captured_packet_t  *orig_entry = &slot->captured_packets[i];
        smugglesnitrick_tcp_packet_info_t orig_info  = {0};

        if (orig_entry->line == NULL || orig_entry->buf == NULL)
        {
            goto fail;
        }

        if (! smugglesnitrickParseTcpPacketInfo(
                (const uint8_t *) sbufGetRawPtr(orig_entry->buf), sbufGetLength(orig_entry->buf), &orig_info))
        {
            goto fail;
        }

        if (i == 0)
        {
            first_seq = orig_info.seq;
        }
        else
        {
            if (orig_info.seq != first_seq + stream_offset)
            {
                goto fail;
            }
        }

        uint32_t orig_buf_len = sbufGetLength(orig_entry->buf);
        sbuf_t  *fake_buf     = clonePacketWithLength(orig_entry->line, orig_entry->buf, orig_buf_len);
        if (fake_buf == NULL)
        {
            goto fail;
        }

        memoryCopyLarge(sbufGetMutablePtr(fake_buf), sbufGetRawPtr(orig_entry->buf), orig_buf_len);

        uint8_t *fake_packet = sbufGetMutablePtr(fake_buf);

        if (stream_offset < tls_record_len)
        {
            uint32_t overwrite_len = min((uint32_t) orig_info.tcp_payload_len, tls_record_len - stream_offset);
            memoryCopyLarge(fake_packet + orig_info.payload_offset, generated_bytes + stream_offset, overwrite_len);
        }

        stream_offset += orig_info.tcp_payload_len;

        smugglesnitrick_tcp_packet_info_t fake_info = {0};
        if (! smugglesnitrickParseTcpPacketInfo(fake_packet, orig_buf_len, &fake_info))
        {
            sbufDestroy(fake_buf);
            goto fail;
        }

        if (fake_info.ip_total_len != orig_info.ip_total_len ||
            fake_info.tcp_payload_len != orig_info.tcp_payload_len || fake_info.seq != orig_info.seq ||
            fake_info.payload_offset != orig_info.payload_offset || fake_info.tcp_flags != orig_info.tcp_flags)
        {
            sbufDestroy(fake_buf);
            goto fail;
        }

        batch->entries[i] = (smugglesnitrick_fake_batch_entry_t) {.line = orig_entry->line, .buf = fake_buf};
        batch->count++;
    }

    if (stream_offset != slot->captured_payload_len)
    {
        goto fail;
    }

    reuseBuffer(tls_hello);
    return true;

fail:
    for (uint8_t i = 0; i < batch->count; ++i)
    {
        if (batch->entries[i].buf != NULL)
        {
            smugglesnitrickCleanupDelayedBuffer(batch->entries[i].line, batch->entries[i].buf);
            batch->entries[i].buf  = NULL;
            batch->entries[i].line = NULL;
        }
    }
    batch->count = 0;
    reuseBuffer(tls_hello);
    return false;
}

/* Runs under the flow-shard lock: dispose retained FIFO packets only. */
static void smugglesnitrickDestroyFlowRecord(void *record, void *context)
{
    discard context;

    ipmanipulator_smuggle_flow_t *flow = record;
    ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
}

bool smugglesnitrickInitializeState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    return ipmanipulatorFlowTableInit(&state->smuggle_table,
                                      "smuggle-sni",
                                      state->trick_stateful_flow_limit,
                                      (uint32_t) getTotalWorkersCount(),
                                      sizeof(ipmanipulator_smuggle_flow_t),
                                      smugglesnitrickDestroyFlowRecord,
                                      NULL);
}

void smugglesnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    ipmanipulatorFlowTableDestroy(&state->smuggle_table);
}

void smugglesnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                       uint16_t dst_port)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state == NULL || ! ipmanipulatorFlowTableIsReady(&state->smuggle_table))
    {
        return;
    }

    ipmanipulator_flow_key_t key = ipmanipulatorFlowKeyMake(src_addr, src_port, dst_addr, dst_port);

    smugglesnitrickMarkPassthrough(state, &key, 0);
}

void smugglesnitrickLogDownStreamServerHello(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineGetWID(l) == getWID());
    discard l;

    smugglesnitrick_tcp_packet_info_t info   = {0};
    const uint8_t                    *packet = (const uint8_t *) sbufGetRawPtr(buf);

    if (! smugglesnitrickParseTcpPacketInfo(packet, sbufGetLength(buf), &info))
    {
        return;
    }

    if (smugglesnitrickHasFinOrRst(&info))
    {
        ipmanipulatorFlushMatchingCaptureSlot(
            t, info.dst_addr, info.src_addr, info.dst_port, info.src_port, kIpManipulatorTlsCaptureKindSmuggleSni);

        ipmanipulator_tstate_t     *state = tunnelGetState(t);
        ipmanipulator_flow_key_t    key   = smugglesnitrickMakeKey(&info);
        ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_table, &key);

        if (shard != NULL)
        {
            /* Downstream traffic runs the reverse orientation of the stored record. */
            ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->smuggle_table, shard, &key);

            if (entry != NULL && ! smugglesnitrickFlowIsForward(smugglesnitrickEntryRecord(entry), &info))
            {
                ipmanipulatorFlowShardRemove(&state->smuggle_table, shard, entry);
            }

            ipmanipulatorFlowShardUnlock(shard);
        }
    }

    if (info.tcp_payload_len < 9)
    {
        return;
    }

    const uint8_t *tls = packet + info.payload_offset;
    if (tls[0] != 0x16 || tls[1] != 0x03 || tls[5] != 0x02)
    {
        return;
    }

    ipmanipulator_tstate_t *state = tunnelGetState(t);

    LOGD("IpManipulator: smuggle-sni saw downstream TLS ServerHello for fake-sni=\"%s\" on %u:%u -> %u:%u",
         state->trick_smuggle_sni_value,
         info.src_addr,
         info.src_port,
         info.dst_addr,
         info.dst_port);
}

bool smugglesnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineGetWID(l) == getWID());

    ipmanipulator_tstate_t           *state                    = tunnelGetState(t);
    smugglesnitrick_tcp_packet_info_t info                     = {0};
    uint64_t                          now_ms                   = getTickMS();
    ipmanipulator_delay_batch_t       release_batch            = {0};
    bool                              needs_schedule           = false;
    bool                              send_current_after_batch = false;
    uint64_t                          barrier_generation       = 0;
    uint64_t                          barrier_deadline         = 0;

    if (! smugglesnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    bool opening_syn = smugglesnitrickIsPureSyn(&info);

    if (opening_syn)
    {
        ipmanipulator_tls_capture_slot_t replaced_capture = {0};

        if (ipmanipulatorTakeMatchingCaptureSlot(t,
                                                 info.src_addr,
                                                 info.dst_addr,
                                                 info.src_port,
                                                 info.dst_port,
                                                 kIpManipulatorTlsCaptureKindSmuggleSni,
                                                 0,
                                                 true,
                                                 &replaced_capture))
        {
            /* A replacement SYN invalidates held bytes from either old orientation. */
            ipmanipulatorRecycleCapturedTlsPackets(t, &replaced_capture);
        }
    }

    ipmanipulator_flow_key_t    key   = smugglesnitrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = smugglesnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = opening_syn ? ipmanipulatorFlowShardFind(&state->smuggle_table, shard, &key)
                                                    : smugglesnitrickFindLocked(state, shard, &key, &info, true);

    if (opening_syn && entry != NULL)
    {
        smugglesnitrickInitializeFlow(smugglesnitrickEntryRecord(entry), &info, now_ms);
    }
    else if (entry == NULL)
    {
        if (! opening_syn)
        {
            ipmanipulatorFlowShardUnlock(shard);
            return false;
        }

        entry = smugglesnitrickReserveLocked(state, shard, &key, &info, now_ms);
    }

    if (entry == NULL)
    {
        ipmanipulatorFlowShardUnlock(shard);
        LOGW("IpManipulator: smuggle-sni could not admit a shared connection record; the packet passes unchanged");
        return false;
    }

    ipmanipulator_smuggle_flow_t *flow = smugglesnitrickEntryRecord(entry);

    smugglesnitrickTouchLocked(shard, entry, now_ms);

    bool transcript_pending = ipmanipulatorDelayBarrierHasPendingOrdered(&flow->delay_barrier);
    if (flow->phase == kIpManipulatorSmuggleFlowPhasePassthrough &&
        (now_ms < flow->delay_window_until_ms || flow->delay_barrier.count > 0 || transcript_pending))
    {
        if (! transcript_pending && now_ms >= flow->delay_window_until_ms && flow->delay_barrier.count > 0)
        {
            ipmanipulatorDelayBarrierTake(&flow->delay_barrier, &release_batch);
            flow->delay_window_until_ms = 0;
            send_current_after_batch    = true;
        }
        else if (ipmanipulatorDelayBarrierTryEnqueue(
                     &flow->delay_barrier, l, buf, smugglesnitrickHasFinOrRst(&info), &needs_schedule))
        {
            barrier_generation = flow->delay_barrier.generation;
            barrier_deadline   = flow->delay_barrier.deadline_ms;
        }
        else
        {
            ipmanipulatorDelayBarrierTake(&flow->delay_barrier, &release_batch);
            flow->delay_window_until_ms = 0;
            send_current_after_batch    = true;
        }

        if (send_current_after_batch && smugglesnitrickHasFinOrRst(&info))
        {
            ipmanipulatorFlowShardRemove(&state->smuggle_table, shard, entry);
        }

        ipmanipulatorFlowShardUnlock(shard);

        if (needs_schedule)
        {
            uint64_t remaining = barrier_deadline > now_ms ? barrier_deadline - now_ms : 0;
            ipmanipulatorDelayBarrierSchedule(t,
                                              &key,
                                              kIpManipulatorDelayBarrierSmuggleSni,
                                              barrier_generation,
                                              lineGetWID(l),
                                              remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining);
        }

        if (! send_current_after_batch)
        {
            return true;
        }

        bool alive = ipmanipulatorDelayBatchSendUpstream(t, &release_batch);
        if (alive && lineIsAlive(l))
        {
            smugglesnitrickSendNormalNow(t, l, buf);
        }
        else
        {
            lineReuseBuffer(l, buf);
        }
        return true;
    }

    if (smugglesnitrickHasFinOrRst(&info))
    {
        ipmanipulatorFlowShardRemove(&state->smuggle_table, shard, entry);
        ipmanipulatorFlowShardUnlock(shard);
        ipmanipulatorFlushMatchingCaptureSlot(
            t, info.src_addr, info.dst_addr, info.src_port, info.dst_port, kIpManipulatorTlsCaptureKindSmuggleSni);
        return false;
    }

    smugglesnitrick_action_e action = kSmuggleSniActionPassNormal;

    switch (flow->phase)
    {
    case kIpManipulatorSmuggleFlowPhaseWarmup:
        flow->warmup_packets_seen += 1;
        if (flow->warmup_packets_seen >= kSmuggleSniWarmupPackets)
        {
            flow->phase = kIpManipulatorSmuggleFlowPhaseCapture;
        }
        action = kSmuggleSniActionPassNormal;
        break;

    case kIpManipulatorSmuggleFlowPhaseCapture:
        action = kSmuggleSniActionCapture;
        break;

    case kIpManipulatorSmuggleFlowPhasePassthrough:
        action = kSmuggleSniActionPassNormal;
        break;
    }

    ipmanipulatorFlowShardUnlock(shard);

    if (action == kSmuggleSniActionPassNormal)
    {
        return false;
    }

    ipmanipulator_tls_capture_slot_t   captured_slot = {0};
    ipmanipulator_tls_capture_status_e status =
        ipmanipulatorCaptureTlsClientHello(t, l, buf, kIpManipulatorTlsCaptureKindSmuggleSni, &captured_slot);

    if (status == kIpManipulatorTlsCaptureStatusPending)
    {
        return true;
    }

    if (status == kIpManipulatorTlsCaptureStatusBypassed)
    {
        smugglesnitrickMarkPassthrough(state, &key, 0);
        return true;
    }

    if (status == kIpManipulatorTlsCaptureStatusMiss)
    {
        smugglesnitrickMarkPassthrough(state, &key, 0);
        return false;
    }

    /* status == kIpManipulatorTlsCaptureStatusReady */
    sni_match_t    match          = {0};
    const uint8_t *assembled_data = (const uint8_t *) sbufGetRawPtr(captured_slot.assembled_packet);
    uint32_t       assembled_len  = sbufGetLength(captured_slot.assembled_packet);

    bool valid_ch = parseClientHelloSni(assembled_data, assembled_len, &match);
    if (valid_ch)
    {
        if (captured_slot.tls_record_total_len != 5U + (uint32_t) match.tls_record_len ||
            captured_slot.tls_record_total_len > captured_slot.captured_payload_len)
        {
            valid_ch = false;
        }
    }

    if (match.has_tls13_psk_binder &&
        (match.sni_name_len != state->trick_smuggle_sni_value_len ||
         memcmp(assembled_data + match.sni_name_offset, state->trick_smuggle_sni_value, match.sni_name_len) != 0))
    {
        LOGD("IpManipulator: smuggle-sni skipping fake ClientHello rewrite because pre_shared_key binders are present");
        valid_ch = false;
    }

    smugglesnitrick_fake_batch_t *batch    = NULL;
    bool                          build_ok = false;

    if (valid_ch)
    {
        batch    = memoryAllocateZero(sizeof(*batch));
        build_ok = smugglesnitrickBuildFakeBatch(t, l, &captured_slot, batch);
    }

    if (! build_ok)
    {
        if (batch != NULL)
        {
            memoryFree(batch);
            batch = NULL;
        }

        ipmanipulatorReleaseCapturedPacketsNormal(t, &captured_slot);
        smugglesnitrickMarkPassthrough(state, &key, 0);
        return true;
    }

    if (captured_slot.assembled_packet != NULL)
    {
        sbufDestroy(captured_slot.assembled_packet);
        captured_slot.assembled_packet = NULL;
    }

    LOGD("IpManipulator: smuggle-sni sent the real packets immediately to \"%s\" and scheduled fake SNI \"%s\" packets "
         "(%u segment(s)) after %u ms",
         state->trick_real_sni_upstream_node->name,
         state->trick_smuggle_sni_value,
         (unsigned int) batch->count,
         (unsigned int) state->trick_smuggle_sni_delay_ms);

    for (uint8_t i = 0; i < captured_slot.captured_packets_count; ++i)
    {
        ipmanipulator_captured_packet_t *captured = &captured_slot.captured_packets[i];
        if (captured->line != NULL && captured->buf != NULL)
        {
            smugglesnitrickSendRealNow(t, captured->line, captured->buf);
            captured->line = NULL;
            captured->buf  = NULL;
        }
    }
    captured_slot.captured_packets_count = 0;

    smugglesnitrickStartOrderedFakeBatch(t, &key, batch, now_ms);
    return true;
}
