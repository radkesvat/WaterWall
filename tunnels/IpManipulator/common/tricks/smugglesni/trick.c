#include "trick.h"

#include "loggers/network_logger.h"

api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message);

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
    kSmuggleSniActionDelayNormal,
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
    if (packet == NULL || info == NULL || packet_length < sizeof(struct ip_hdr))
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

    uint16_t ip_header_len = (uint16_t) (ip_hdr_len_words * 4U);
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

    uint16_t tcp_header_len = (uint16_t) (tcp_hdr_len_words * 4U);
    uint16_t headers_len    = (uint16_t) (ip_header_len + tcp_header_len);
    if (ip_total_len < headers_len)
    {
        return false;
    }

    *info = (smugglesnitrick_tcp_packet_info_t) {
        .src_addr        = ipheader->src.addr,
        .dst_addr        = ipheader->dest.addr,
        .seq             = lwip_ntohl(tcp_header->seqno),
        .payload_offset  = headers_len,
        .tcp_flags       = TCPH_FLAGS(tcp_header),
        .src_port        = lwip_ntohs(tcp_header->src),
        .dst_port        = lwip_ntohs(tcp_header->dest),
        .ip_total_len    = ip_total_len,
        .tcp_payload_len = (uint16_t) (ip_total_len - headers_len),
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
    *flow = (ipmanipulator_smuggle_flow_t) {
        .created_ms       = now_ms,
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .phase            = kIpManipulatorSmuggleFlowPhaseWarmup,
    };
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
    }

    ipmanipulatorFlowShardUnlock(shard);
}

static void smugglesnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    lineSetRecalculateChecksum(l, true);
    ipmanipulatorEmitUpstream(t, l, buf, tunnelNextUpStreamPayload);
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

static void smugglesnitrickRunDelayedNormal(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;

    tunnel_t *t   = arg1;
    line_t   *l   = arg2;
    sbuf_t   *buf = arg3;

    if (lineIsAlive(l))
    {
        smugglesnitrickSendNormalNow(t, l, buf);
    }
    else
    {
        lineReuseBuffer(l, buf);
    }

    lineUnlock(l);
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

static void smugglesnitrickCleanupDelayedNormal(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    line_t *l   = arg2;
    sbuf_t *buf = arg3;

    smugglesnitrickCleanupDelayedBuffer(l, buf);
    lineUnlock(l);
}

static void smugglesnitrickScheduleNormalSend(tunnel_t *t, line_t *l, sbuf_t *buf, uint32_t delay_ms)
{
    if (delay_ms == 0 && getWID() == lineGetWID(l))
    {
        smugglesnitrickSendNormalNow(t, l, buf);
        return;
    }

    lineLock(l);
    sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                      (WorkerMessageCallback) smugglesnitrickRunDelayedNormal,
                                      smugglesnitrickCleanupDelayedNormal,
                                      delay_ms,
                                      t,
                                      l,
                                      buf);
}

static sbuf_t *smugglesnitrickAllocateRequestBuffer(uint32_t len)
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

sbuf_t *smugglesnitrickGenerateTlsClientHello(tunnel_t *t)
{
    static const char kGenerateTlsHelloPrefix[] = "generateTlsHello:";

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    uint32_t request_len = (uint32_t) (sizeof(kGenerateTlsHelloPrefix) - 1) + state->trick_smuggle_sni_value_len;
    sbuf_t  *request_buf = smugglesnitrickAllocateRequestBuffer(request_len);

    if (request_buf == NULL)
    {
        return NULL;
    }

    sbufSetLength(request_buf, request_len);
    memoryCopy(sbufGetMutablePtr(request_buf), kGenerateTlsHelloPrefix, sizeof(kGenerateTlsHelloPrefix) - 1);
    memoryCopy(sbufGetMutablePtr(request_buf) + (sizeof(kGenerateTlsHelloPrefix) - 1),
               state->trick_smuggle_sni_value,
               state->trick_smuggle_sni_value_len);

    api_result_t result = tlsclientTunnelApi(state->trick_real_sni_tls_client_tunnel, request_buf);

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

static bool smugglesnitrickBuildFakeBatch(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot,
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

    sbuf_t *tls_hello = smugglesnitrickGenerateTlsClientHello(t);
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

typedef struct smugglesnitrick_fake_batch_msg_s
{
    smugglesnitrick_fake_batch_t *batch;
} smugglesnitrick_fake_batch_msg_t;

static void smugglesnitrickRunDelayedBatchOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg3;

    tunnel_t                         *t   = arg1;
    smugglesnitrick_fake_batch_msg_t *msg = arg2;

    if (msg != NULL && msg->batch != NULL)
    {
        smugglesnitrick_fake_batch_t *batch = msg->batch;
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
                lineUnlock(entry->line);
                entry->line = NULL;
                entry->buf  = NULL;
            }
        }
        memoryFree(batch);
        msg->batch = NULL;
    }

    memoryFree(msg);
}

static void smugglesnitrickCleanupDelayedBatch(void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg3;

    smugglesnitrick_fake_batch_msg_t *msg = arg2;
    if (msg == NULL)
    {
        return;
    }

    if (msg->batch != NULL)
    {
        smugglesnitrick_fake_batch_t *batch = msg->batch;
        for (uint8_t i = 0; i < batch->count; ++i)
        {
            smugglesnitrick_fake_batch_entry_t *entry = &batch->entries[i];
            if (entry->line != NULL && entry->buf != NULL)
            {
                smugglesnitrickCleanupDelayedBuffer(entry->line, entry->buf);
                lineUnlock(entry->line);
                entry->line = NULL;
                entry->buf  = NULL;
            }
        }
        memoryFree(batch);
        msg->batch = NULL;
    }

    memoryFree(msg);
}

static void smugglesnitrickScheduleBatchSend(tunnel_t *t, smugglesnitrick_fake_batch_t *batch, uint32_t delay_ms)
{
    if (batch == NULL || batch->count == 0)
    {
        if (batch != NULL)
        {
            memoryFree(batch);
        }
        return;
    }

    line_t *first_line = batch->entries[0].line;
    if (first_line == NULL)
    {
        for (uint8_t i = 0; i < batch->count; ++i)
        {
            if (batch->entries[i].buf != NULL)
            {
                sbufDestroy(batch->entries[i].buf);
            }
        }
        memoryFree(batch);
        return;
    }

    wid_t target_wid = lineGetWID(first_line);

    if (delay_ms == 0 && getWID() == target_wid)
    {
        for (uint8_t i = 0; i < batch->count; ++i)
        {
            smugglesnitrick_fake_batch_entry_t *entry = &batch->entries[i];
            if (entry->line != NULL && entry->buf != NULL)
            {
                smugglesnitrickSendNormalNow(t, entry->line, entry->buf);
                entry->buf  = NULL;
                entry->line = NULL;
            }
        }
        memoryFree(batch);
        return;
    }

    smugglesnitrick_fake_batch_msg_t *msg = memoryAllocate(sizeof(*msg));
    msg->batch                            = batch;

    for (uint8_t i = 0; i < batch->count; ++i)
    {
        lineLock(batch->entries[i].line);
    }

    sendWorkerMessageTimedWithCleanup(target_wid,
                                      (WorkerMessageCallback) smugglesnitrickRunDelayedBatchOnWorker,
                                      smugglesnitrickCleanupDelayedBatch,
                                      delay_ms,
                                      t,
                                      msg,
                                      NULL);
}

bool smugglesnitrickInitializeState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    /* A Smuggle-SNI record owns no buffers, so it needs no resource destructor. */
    return ipmanipulatorFlowTableInit(&state->smuggle_table,
                                      "smuggle-sni",
                                      state->trick_stateful_flow_limit,
                                      (uint32_t) getTotalWorkersCount(),
                                      sizeof(ipmanipulator_smuggle_flow_t),
                                      NULL,
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

    ipmanipulator_tstate_t           *state  = tunnelGetState(t);
    smugglesnitrick_tcp_packet_info_t info   = {0};
    uint64_t                          now_ms = getTickMS();

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
        action = (now_ms < flow->delay_window_until_ms) ? kSmuggleSniActionDelayNormal : kSmuggleSniActionPassNormal;
        break;
    }

    ipmanipulatorFlowShardUnlock(shard);

    if (action == kSmuggleSniActionDelayNormal)
    {
        smugglesnitrickScheduleNormalSend(t, l, buf, state->trick_smuggle_sni_delay_ms);
        return true;
    }

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
        build_ok = smugglesnitrickBuildFakeBatch(t, &captured_slot, batch);
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

    smugglesnitrickScheduleBatchSend(t, batch, state->trick_smuggle_sni_delay_ms);

    smugglesnitrickMarkPassthrough(state, &key, now_ms + kSmuggleSniDelayWindowMs);
    return true;
}
