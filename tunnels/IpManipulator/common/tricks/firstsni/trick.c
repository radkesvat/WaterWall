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

static void firstsnitrickInitializeFlow(ipmanipulator_firstsni_flow_t         *flow,
                                        const firstsnitrick_tcp_packet_info_t *info, uint64_t now_ms)
{
    if (flow == NULL || info == NULL)
    {
        return;
    }

    ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
    uint64_t barrier_generation = flow->delay_barrier.generation;

    *flow = (ipmanipulator_firstsni_flow_t) {
        .created_ms            = now_ms,
        .last_activity_ms      = now_ms,
        .delay_window_until_ms = 0,
        .src_addr              = info->src_addr,
        .dst_addr              = info->dst_addr,
        .src_port              = info->src_port,
        .dst_port              = info->dst_port,
    };
    flow->delay_barrier.generation = barrier_generation;
}

static bool firstsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                            firstsnitrick_tcp_packet_info_t *info)
{
    ipv4_packet_view_t packet_view = {0};
    if (info == NULL || ! ipv4packetviewParseTcp(packet, packet_length, &packet_view) || packet_view.fragmented)
    {
        return false;
    }

    *info = (firstsnitrick_tcp_packet_info_t) {
        .src_addr        = packet_view.source_address,
        .dst_addr        = packet_view.destination_address,
        .seq             = packet_view.tcp_sequence,
        .ip_total_len    = packet_view.ip_total_length,
        .src_port        = packet_view.source_port,
        .dst_port        = packet_view.destination_port,
        .tcp_payload_len = packet_view.payload_length,
        .tcp_flags       = packet_view.tcp_flags,
        .ttl             = packet_view.ttl,
    };

    return true;
}

static bool firstsnitrickIsPureSyn(const firstsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && ipmanipulatorIsFlowOpeningSyn(info->tcp_flags, info->tcp_payload_len);
}

static bool firstsnitrickHasFinOrRst(const firstsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static ipmanipulator_flow_key_t firstsnitrickMakeKey(const firstsnitrick_tcp_packet_info_t *info)
{
    return ipmanipulatorFlowKeyMake(info->src_addr, info->src_port, info->dst_addr, info->dst_port);
}

static ipmanipulator_firstsni_flow_t *firstsnitrickEntryRecord(ipmanipulator_flow_entry_t *entry)
{
    return (ipmanipulator_firstsni_flow_t *) ipmanipulatorFlowEntryRecord(entry);
}

/*
 * Locks the shard that owns this tuple and reclaims a bounded number of expired
 * entries. Returns NULL when the trick is not configured.
 */
static ipmanipulator_flow_shard_t *firstsnitrickLockShard(ipmanipulator_tstate_t         *state,
                                                          const ipmanipulator_flow_key_t *key, uint64_t now_ms)
{
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->first_sni_table, key);

    if (shard != NULL)
    {
        discard ipmanipulatorFlowShardExpire(&state->first_sni_table, shard, now_ms, kIpManipulatorFlowCleanupBudget);
    }

    return shard;
}

static void firstsnitrickTouchLocked(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                     ipmanipulator_firstsni_flow_t *flow, uint64_t now_ms)
{
    flow->last_activity_ms = now_ms;
    ipmanipulatorFlowShardTouch(shard, entry, now_ms + kFirstSniIdleTimeoutMs);
}

static ipmanipulator_flow_entry_t *firstsnitrickReserveLocked(ipmanipulator_tstate_t                *state,
                                                              ipmanipulator_flow_shard_t            *shard,
                                                              const ipmanipulator_flow_key_t        *key,
                                                              const firstsnitrick_tcp_packet_info_t *info,
                                                              uint64_t                               now_ms)
{
    ipmanipulator_flow_entry_t *entry =
        ipmanipulatorFlowShardReserve(&state->first_sni_table, shard, key, now_ms, now_ms + kFirstSniIdleTimeoutMs);

    if (entry == NULL)
    {
        return NULL;
    }

    firstsnitrickInitializeFlow(firstsnitrickEntryRecord(entry), info, now_ms);
    return entry;
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

static void firstsnitrickSendPreparedBatchNow(tunnel_t *t, line_t *l, sbuf_t **packets, uint8_t count)
{
    if (! lineIsAlive(l))
    {
        for (uint8_t i = 0; i < count; ++i)
        {
            if (packets[i] != NULL)
            {
                lineReuseBuffer(l, packets[i]);
                packets[i] = NULL;
            }
        }
        return;
    }

    lineRef(l);

    bool alive = lineIsAlive(l);
    for (uint8_t i = 0; i < count; ++i)
    {
        if (packets[i] == NULL)
        {
            continue;
        }

        if (alive)
        {
            alive = ipmanipulatorSendUpstreamMaybeSegmented(t, l, packets[i]);
        }
        else
        {
            lineReuseBuffer(l, packets[i]);
        }
        packets[i] = NULL;
    }

    lineUnref(l);
}

static void firstsnitrickSendOrderedNow(tunnel_t *t, ipmanipulator_ordered_output_t *outputs, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i)
    {
        ipmanipulator_ordered_output_t *output = &outputs[i];

        if (output->line == NULL || output->buf == NULL)
        {
            continue;
        }

        if (! lineIsOnCurrentEventWorker(output->line))
        {
            ipmanipulatorForwardCapturedPacketNormal(t, output->line, output->buf);
        }
        else if (lineIsAlive(output->line))
        {
            lineRef(output->line);
            output->send(t, output->line, output->buf);
            lineUnref(output->line);
        }
        else
        {
            lineReuseBuffer(output->line, output->buf);
        }
        output->line = NULL;
        output->buf  = NULL;
    }
}

/*
 * Installs the transcript tail as the first FIFO entries. Later flow packets
 * therefore cannot overtake the delayed original ClientHello even when a fake
 * scheduler executes equal-deadline timers in reverse insertion order.
 */
static void firstsnitrickStartDelayBarrier(tunnel_t *t, line_t *l, sbuf_t **packets, uint8_t count,
                                           ipmanipulator_ordered_output_t *ordered_outputs,
                                           uint32_t ordered_outputs_count, uint64_t deadline_ms, uint64_t now_ms)
{
    ipmanipulator_tstate_t         *state = tunnelGetState(t);
    firstsnitrick_tcp_packet_info_t info  = {0};

    if (count == 0 || packets == NULL || packets[count - 1U] == NULL ||
        ! ipmanipulatorFlowTableIsReady(&state->first_sni_table) ||
        ! firstsnitrickParseTcpPacketInfo(
            (const uint8_t *) sbufGetRawPtr(packets[count - 1U]), sbufGetLength(packets[count - 1U]), &info))
    {
        firstsnitrickSendOrderedNow(t, ordered_outputs, ordered_outputs_count);
        firstsnitrickSendPreparedBatchNow(t, l, packets, count);
        return;
    }

    ipmanipulator_flow_key_t    key   = firstsnitrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = firstsnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        firstsnitrickSendOrderedNow(t, ordered_outputs, ordered_outputs_count);
        firstsnitrickSendPreparedBatchNow(t, l, packets, count);
        return;
    }

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->first_sni_table, shard, &key);
    if (entry == NULL)
    {
        entry = firstsnitrickReserveLocked(state, shard, &key, &info, now_ms);
    }

    if (entry != NULL)
    {
        ipmanipulator_firstsni_flow_t *flow = firstsnitrickEntryRecord(entry);

        flow->delay_window_until_ms = deadline_ms;
        ipmanipulatorDelayBarrierInitialize(state, &flow->delay_barrier, deadline_ms);

        bool     needs_schedule  = false;
        bool     ordered_ok      = ordered_outputs_count == 0;
        uint64_t first_action_ms = deadline_ms;

        if (ordered_outputs_count > 0)
        {
            first_action_ms = ordered_outputs[0].due_ms;
            ordered_ok      = ipmanipulatorDelayBarrierInstallOrdered(t,
                                                                 kIpManipulatorDelayBarrierFirstSni,
                                                                 &flow->delay_barrier,
                                                                 ordered_outputs,
                                                                 ordered_outputs_count,
                                                                 &needs_schedule);
        }

        if (! ordered_ok)
        {
            flow->delay_window_until_ms = 0;
            ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
            ipmanipulatorFlowShardUnlock(shard);
            firstsnitrickSendOrderedNow(t, ordered_outputs, ordered_outputs_count);
            firstsnitrickSendPreparedBatchNow(t, l, packets, count);
            return;
        }

        bool enqueue_ok = true;
        for (uint8_t i = 0; i < count; ++i)
        {
            bool packet_needs_schedule = false;
            if (! ipmanipulatorDelayBarrierTryEnqueue(t,
                                                      kIpManipulatorDelayBarrierFirstSni,
                                                      &flow->delay_barrier,
                                                      l,
                                                      packets[i],
                                                      false,
                                                      &packet_needs_schedule))
            {
                enqueue_ok = false;
                break;
            }
            packets[i] = NULL;
            needs_schedule |= packet_needs_schedule;
        }

        if (! enqueue_ok)
        {
            ipmanipulator_delay_batch_t release_batch = {0};
            ipmanipulatorDelayBarrierTake(&flow->delay_barrier, &release_batch);
            flow->delay_window_until_ms = 0;
            ipmanipulatorFlowShardUnlock(shard);
            discard ipmanipulatorDelayBatchSendUpstream(t, &release_batch);
            firstsnitrickSendPreparedBatchNow(t, l, packets, count);
            return;
        }

        uint64_t generation = flow->delay_barrier.generation;
        wid_t    owner_wid  = flow->delay_barrier.owner_wid;
        firstsnitrickTouchLocked(shard, entry, flow, now_ms);
        ipmanipulatorFlowShardUnlock(shard);

        if (needs_schedule)
        {
            uint64_t remaining = first_action_ms > now_ms ? first_action_ms - now_ms : 0;
            if (! ipmanipulatorDelayBarrierSchedule(t,
                                                    &key,
                                                    kIpManipulatorDelayBarrierFirstSni,
                                                    generation,
                                                    owner_wid,
                                                    remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining))
            {
                ipmanipulatorDelayBarrierFailOpen(t, &key, kIpManipulatorDelayBarrierFirstSni, generation);
            }
        }
        return;
    }

    ipmanipulatorFlowShardUnlock(shard);

    LOGW("IpManipulator: first-sni could not admit a flow record for delayed replay handling; the transcript tail "
         "is forwarded immediately");
    firstsnitrickSendOrderedNow(t, ordered_outputs, ordered_outputs_count);
    firstsnitrickSendPreparedBatchNow(t, l, packets, count);
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

    struct tcp_hdr *tcph     = (struct tcp_hdr *) (packet + ip_hlen);
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

    uint32_t original_packet_len      = match->ip_total_len;
    int32_t  delta                    = (int32_t) state->trick_first_sni_value_len - (int32_t) match->sni_name_len;
    int32_t  new_ip_total_len         = (int32_t) match->ip_total_len + delta;
    int32_t  new_extensions_len       = (int32_t) match->extensions_len + delta;
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

    uint8_t *dest        = sbufGetMutablePtr(clone);
    uint32_t prefix_len  = match->sni_name_offset;
    uint32_t tail_offset = match->sni_name_offset + match->sni_name_len;
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
    ipmanipulator_tstate_t     *state                    = tunnelGetState(t);
    uint32_t                    tail_delay_ms            = firstsnitrickGetTailDelayMs(state);
    ipmanipulator_delay_batch_t release_batch            = {0};
    bool                        queued                   = false;
    bool                        needs_schedule           = false;
    bool                        send_current_after_batch = false;
    uint64_t                    generation               = 0;
    uint64_t                    deadline_ms              = 0;
    wid_t                       barrier_owner_wid        = kInvalidWID;

    if (! ipmanipulatorFlowTableIsReady(&state->first_sni_table) || tail_delay_ms == 0 || info == NULL)
    {
        return false;
    }

    ipmanipulator_flow_key_t    key   = firstsnitrickMakeKey(info);
    ipmanipulator_flow_shard_t *shard = firstsnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->first_sni_table, shard, &key);

    if (firstsnitrickIsPureSyn(info))
    {
        /* A new handshake on this tuple starts a fresh, delay-free flow. */
        if (entry != NULL)
        {
            firstsnitrickInitializeFlow(firstsnitrickEntryRecord(entry), info, now_ms);
        }
        else
        {
            entry = firstsnitrickReserveLocked(state, shard, &key, info, now_ms);
        }
    }

    bool delay_active = false;

    if (entry != NULL)
    {
        ipmanipulator_firstsni_flow_t *flow = firstsnitrickEntryRecord(entry);

        firstsnitrickTouchLocked(shard, entry, flow, now_ms);
        bool transcript_pending = ipmanipulatorDelayBarrierHasPendingOrdered(&flow->delay_barrier);
        delay_active = now_ms < flow->delay_window_until_ms || flow->delay_barrier.count > 0 || transcript_pending;

        if (delay_active && ! transcript_pending && now_ms >= flow->delay_window_until_ms &&
            flow->delay_barrier.count > 0)
        {
            ipmanipulatorDelayBarrierTake(&flow->delay_barrier, &release_batch);
            flow->delay_window_until_ms = 0;
            delay_active                = false;
            send_current_after_batch    = true;
        }
        else if (delay_active)
        {
            queued = ipmanipulatorDelayBarrierTryEnqueue(t,
                                                         kIpManipulatorDelayBarrierFirstSni,
                                                         &flow->delay_barrier,
                                                         l,
                                                         buf,
                                                         firstsnitrickHasFinOrRst(info),
                                                         &needs_schedule);
            if (queued)
            {
                generation        = flow->delay_barrier.generation;
                deadline_ms       = flow->delay_barrier.deadline_ms;
                barrier_owner_wid = flow->delay_barrier.owner_wid;
            }
            else
            {
                /* Bounded fail-open: older packets leave before the current one. */
                ipmanipulatorDelayBarrierTake(&flow->delay_barrier, &release_batch);
                flow->delay_window_until_ms = 0;
                delay_active                = false;
                send_current_after_batch    = true;
            }
        }

        if (! delay_active && firstsnitrickHasFinOrRst(info))
        {
            ipmanipulatorFlowShardRemove(&state->first_sni_table, shard, entry);
        }
    }

    ipmanipulatorFlowShardUnlock(shard);

    if (needs_schedule)
    {
        uint64_t remaining = deadline_ms > now_ms ? deadline_ms - now_ms : 0;
        if (! ipmanipulatorDelayBarrierSchedule(t,
                                                &key,
                                                kIpManipulatorDelayBarrierFirstSni,
                                                generation,
                                                barrier_owner_wid,
                                                remaining > UINT32_MAX ? UINT32_MAX : (uint32_t) remaining))
        {
            ipmanipulatorDelayBarrierFailOpen(t, &key, kIpManipulatorDelayBarrierFirstSni, generation);
        }
    }

    if (send_current_after_batch)
    {
        bool alive = ipmanipulatorDelayBatchSendUpstream(t, &release_batch);
        if (alive && lineIsAlive(l))
        {
            firstsnitrickSendOriginalPacket(t, l, buf);
        }
        else
        {
            lineReuseBuffer(l, buf);
        }
        return true;
    }

    if (! delay_active || ! queued)
    {
        return false;
    }

    LOGD("IpManipulator: first-sni queued flow packet payload=%u until absolute replay/final-delay deadline %llu",
         (unsigned int) info->tcp_payload_len,
         (unsigned long long) deadline_ms);
    return true;
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

    lineRef(l);

    firstsnitrickSendCraftedPacket(t, l, fake_packet);

    if (! lineIsAlive(l))
    {
        reuseBuffer(buf);
        lineUnref(l);
        return true;
    }

    if (state->trick_first_sni_count == 1)
    {
        if (state->trick_first_sni_final_delay_ms > 0)
        {
            sbuf_t *barrier_packets[] = {buf};
            firstsnitrickStartDelayBarrier(
                t, l, barrier_packets, 1, NULL, 0, now_ms + state->trick_first_sni_final_delay_ms, now_ms);
            lineUnref(l);
            return true;
        }

        firstsnitrickSendOriginalPacket(t, l, buf);
        lineUnref(l);
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
                lineUnref(l);
                return true;
            }
        }

        if (state->trick_first_sni_final_delay_ms > 0)
        {
            sbuf_t *barrier_packets[] = {buf};
            firstsnitrickStartDelayBarrier(
                t, l, barrier_packets, 1, NULL, 0, now_ms + state->trick_first_sni_final_delay_ms, now_ms);
            lineUnref(l);
            return true;
        }

        firstsnitrickSendOriginalPacket(t, l, buf);
        lineUnref(l);
        return true;
    }

    uint32_t ordered_capacity = state->trick_first_sni_count - 1U;
    /* Keep this multiplication safe on every supported 32-bit or 64-bit build. */
    if (ordered_capacity > UINT32_MAX / sizeof(ipmanipulator_ordered_output_t))
    {
        firstsnitrickSendOriginalPacket(t, l, buf);
        lineUnref(l);
        return true;
    }

    ipmanipulator_ordered_output_t *ordered_outputs = memoryAllocateZero(sizeof(*ordered_outputs) * ordered_capacity);
    if (ordered_outputs == NULL)
    {
        firstsnitrickSendOriginalPacket(t, l, buf);
        lineUnref(l);
        return true;
    }

    uint32_t ordered_count = 0;

    for (uint32_t replay_index = 1; replay_index < state->trick_first_sni_count; ++replay_index)
    {
        sbuf_t *scheduled_packet = craftFirstSniPacket(t, l, buf, &match);
        if (scheduled_packet == NULL)
        {
            break;
        }

        uint32_t delay_ms                = replay_index * state->trick_first_sni_replay_delay_ms;
        ordered_outputs[ordered_count++] = (ipmanipulator_ordered_output_t) {
            .line   = l,
            .buf    = scheduled_packet,
            .send   = firstsnitrickSendCraftedPacket,
            .due_ms = now_ms + delay_ms,
        };
    }

    sbuf_t *barrier_packets[] = {buf};

    firstsnitrickStartDelayBarrier(
        t, l, barrier_packets, 1, ordered_outputs, ordered_count, now_ms + tail_delay_ms, now_ms);
    memoryFree(ordered_outputs);

    lineUnref(l);
    return true;
}

bool firstsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));

    firstsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                        now_ms = getTickMS();

    if (firstsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info) &&
        firstsnitrickMaybeDelayFlowPacket(t, l, buf, &info, now_ms))
    {
        return true;
    }

    if (firstsnitrickHandleClientHello(t, l, buf, now_ms))
    {
        return true;
    }

    ipmanipulator_tls_capture_slot_t   captured_slot = {0};
    ipmanipulator_tls_capture_status_e capture_status =
        ipmanipulatorCaptureTlsClientHello(t, l, buf, kIpManipulatorTlsCaptureKindFirstSni, &captured_slot);

    if (capture_status == kIpManipulatorTlsCaptureStatusPending ||
        capture_status == kIpManipulatorTlsCaptureStatusBypassed)
    {
        return true;
    }

    if (capture_status == kIpManipulatorTlsCaptureStatusReady)
    {
        sbuf_t *captured_packet        = captured_slot.assembled_packet;
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

/* Runs under the flow-shard lock: recycle retained packets only. */
static void firstsnitrickDestroyFlowRecord(void *record, void *context)
{
    discard context;

    ipmanipulator_firstsni_flow_t *flow = record;
    ipmanipulatorDelayBarrierDestroy(&flow->delay_barrier);
}

bool firstsnitrickInitializeState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    return ipmanipulatorFlowTableInit(&state->first_sni_table,
                                      "first-sni",
                                      state->trick_stateful_flow_limit,
                                      (uint32_t) getTotalWorkersCount(),
                                      sizeof(ipmanipulator_firstsni_flow_t),
                                      firstsnitrickDestroyFlowRecord,
                                      NULL);
}

void firstsnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    ipmanipulatorFlowTableDestroy(&state->first_sni_table);
}
