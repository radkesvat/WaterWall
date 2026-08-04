#include "trick.h"

#include "TlsClient/interface.h"
#include "loggers/network_logger.h"

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
    sbuf_t  *packets[kSynfinSniMaxEmittedPackets];
    uint16_t count;
} synfinsnitrick_packet_sequence_t;

typedef struct synfinsnitrick_hold_timeout_s
{
    ipmanipulator_flow_key_t key;
    uint64_t                 generation;
} synfinsnitrick_hold_timeout_t;

#ifdef IPMANIPULATOR_SYNFIN_TEST_HOOKS
typedef void (*synfinsnitrick_test_recycle_hook_t)(sbuf_t *buf);

static synfinsnitrick_test_recycle_hook_t synfinsnitrick_test_recycle_hook;

void ipmanipulatorSynfinTestSetRecycleHook(synfinsnitrick_test_recycle_hook_t hook);
void ipmanipulatorSynfinTestSendOutputs(tunnel_t *t, line_t *l, sbuf_t **packets, uint16_t count);
void ipmanipulatorSynfinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                          WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                          void *arg2, void *arg3);
#endif

static void synfinsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf);

static void synfinsnitrickFinalizePacketChecksum(sbuf_t *packet_buf, uint16_t ip_header_len, bool random_checksum)
{
    if (packet_buf == NULL)
    {
        return;
    }

    uint8_t *packet  = sbufGetMutablePtr(packet_buf);
    uint32_t pkt_len = sbufGetLength(packet_buf);
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
        calcFullPacketChecksum(packet, pkt_len);
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

/* The caller owns the record's retained line reference after a successful take. */
static bool synfinsnitrickTakeHeldPacketLocked(ipmanipulator_synfin_flow_t     *flow,
                                               ipmanipulator_captured_packet_t *held_packet)
{
    if (flow == NULL || held_packet == NULL)
    {
        return false;
    }

    *held_packet           = flow->held_packet;
    flow->held_packet      = (ipmanipulator_captured_packet_t) {0};
    flow->hold_timer_armed = false;
    flow->hold_generation  = 0;
    return held_packet->line != NULL || held_packet->buf != NULL;
}

static void synfinsnitrickDestroyHeldPacketLocked(ipmanipulator_synfin_flow_t *flow)
{
    ipmanipulator_captured_packet_t held_packet = {0};

    if (! synfinsnitrickTakeHeldPacketLocked(flow, &held_packet))
    {
        return;
    }

    line_t *held_line = held_packet.line;
    synfinsnitrickDestroyCapturedPacket(&held_packet);
    if (held_line != NULL)
    {
        lineUnlock(held_line);
    }
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

    synfinsnitrickDestroyHeldPacketLocked(flow);
    synfinsnitrickDestroyStandalonePacket(&flow->syn_packet_template);
    synfinsnitrickResetFlow(flow);
}

static void synfinsnitrickInitializeFlow(ipmanipulator_synfin_flow_t            *flow,
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

    synfinsnitrickDestroyHeldPacketLocked(flow);
    synfinsnitrickDestroyStandalonePacket(&flow->syn_packet_template);
    synfinsnitrickResetFlow(flow);

    *flow = (ipmanipulator_synfin_flow_t) {
        .created_ms          = now_ms,
        .last_activity_ms    = now_ms,
        .src_addr            = info->src_addr,
        .dst_addr            = info->dst_addr,
        .src_port            = info->src_port,
        .dst_port            = info->dst_port,
        .phase               = kIpManipulatorSynfinFlowPhaseWarmup,
        .syn_packet_template = syn_packet_template,
    };
}

static void synfinsnitrickFinalizeFlowLocked(ipmanipulator_synfin_flow_t *flow, bool block_flow)
{
    if (flow == NULL)
    {
        return;
    }

    synfinsnitrickDestroyHeldPacketLocked(flow);
    flow->warmup_packets_seen = kSynfinSniWarmupPackets;
    flow->phase = block_flow ? kIpManipulatorSynfinFlowPhaseBlocked : kIpManipulatorSynfinFlowPhasePassthrough;
}

static bool synfinsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                             synfinsnitrick_tcp_packet_info_t *info)
{
    ipv4_packet_view_t packet_view = {0};
    if (info == NULL || ! ipv4packetviewParseTcp(packet, packet_length, &packet_view) || packet_view.fragmented)
    {
        return false;
    }

    *info = (synfinsnitrick_tcp_packet_info_t) {
        .packet            = packet,
        .seq               = packet_view.tcp_sequence,
        .ack               = packet_view.tcp_acknowledgment,
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

static bool synfinsnitrickIsPureSyn(const synfinsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && ipmanipulatorIsFlowOpeningSyn(info->tcp_flags, info->tcp_payload_len);
}

static bool synfinsnitrickHasFinOrRst(const synfinsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

static ipmanipulator_flow_key_t synfinsnitrickMakeKey(const synfinsnitrick_tcp_packet_info_t *info)
{
    return ipmanipulatorFlowKeyMake(info->src_addr, info->src_port, info->dst_addr, info->dst_port);
}

static ipmanipulator_synfin_flow_t *synfinsnitrickEntryRecord(ipmanipulator_flow_entry_t *entry)
{
    return (ipmanipulator_synfin_flow_t *) ipmanipulatorFlowEntryRecord(entry);
}

/* The record keeps the client-to-server orientation the transcript logic uses. */
static bool synfinsnitrickFlowIsForward(const ipmanipulator_synfin_flow_t      *flow,
                                        const synfinsnitrick_tcp_packet_info_t *info)
{
    return flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr && flow->src_port == info->src_port &&
           flow->dst_port == info->dst_port;
}

static ipmanipulator_flow_shard_t *synfinsnitrickLockShard(ipmanipulator_tstate_t         *state,
                                                           const ipmanipulator_flow_key_t *key, uint64_t now_ms)
{
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->synfin_table, key);

    if (shard != NULL)
    {
        discard ipmanipulatorFlowShardExpire(&state->synfin_table, shard, now_ms, kIpManipulatorFlowCleanupBudget);
    }

    return shard;
}

static void synfinsnitrickTouchLocked(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                      uint64_t now_ms)
{
    synfinsnitrickEntryRecord(entry)->last_activity_ms = now_ms;
    ipmanipulatorFlowShardTouch(shard, entry, now_ms + kSynfinSniIdleTimeoutMs);
}

static ipmanipulator_flow_entry_t *synfinsnitrickFindLocked(ipmanipulator_tstate_t                 *state,
                                                            ipmanipulator_flow_shard_t             *shard,
                                                            const ipmanipulator_flow_key_t         *key,
                                                            const synfinsnitrick_tcp_packet_info_t *info)
{
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->synfin_table, shard, key);

    if (entry != NULL && ! synfinsnitrickFlowIsForward(synfinsnitrickEntryRecord(entry), info))
    {
        return NULL;
    }

    return entry;
}

static ipmanipulator_flow_entry_t *synfinsnitrickReserveLocked(ipmanipulator_tstate_t                 *state,
                                                               ipmanipulator_flow_shard_t             *shard,
                                                               const ipmanipulator_flow_key_t         *key,
                                                               const synfinsnitrick_tcp_packet_info_t *info,
                                                               const sbuf_t *syn_packet_buf, uint64_t now_ms)
{
    ipmanipulator_flow_entry_t *entry =
        ipmanipulatorFlowShardReserve(&state->synfin_table, shard, key, now_ms, now_ms + kSynfinSniIdleTimeoutMs);

    if (entry == NULL)
    {
        return NULL;
    }

    synfinsnitrickInitializeFlow(synfinsnitrickEntryRecord(entry), info, syn_packet_buf, now_ms);
    return entry;
}

static void synfinsnitrickReleaseTimedOutHold(tunnel_t *t, const ipmanipulator_flow_key_t *key, uint64_t generation)
{
    ipmanipulator_tstate_t         *state       = tunnelGetState(t);
    ipmanipulator_captured_packet_t held_packet = {0};
    ipmanipulator_flow_shard_t     *shard       = ipmanipulatorFlowTableLockShard(&state->synfin_table, key);

    if (shard != NULL)
    {
        ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->synfin_table, shard, key);

        if (entry != NULL)
        {
            ipmanipulator_synfin_flow_t *flow = synfinsnitrickEntryRecord(entry);

            if (flow->phase == kIpManipulatorSynfinFlowPhaseHoldThird && flow->hold_timer_armed &&
                flow->hold_generation == generation)
            {
                discard synfinsnitrickTakeHeldPacketLocked(flow, &held_packet);
                flow->phase = kIpManipulatorSynfinFlowPhasePassthrough;
                synfinsnitrickDestroyStandalonePacket(&flow->syn_packet_template);
                synfinsnitrickTouchLocked(shard, entry, getTickMS());
            }
        }

        ipmanipulatorFlowShardUnlock(shard);
    }

    if (held_packet.line != NULL || held_packet.buf != NULL)
    {
        LOGD("IpManipulator: synfin-sni hold timed out after %u ms; releasing the segment unchanged",
             state->trick_synfin_sni_hold_timeout_ms);

        line_t *held_line = held_packet.line;
        if (held_line != NULL && held_packet.buf != NULL)
        {
            synfinsnitrickSendNormalNow(t, held_line, held_packet.buf);
        }
        else if (held_packet.buf != NULL)
        {
            sbufDestroy(held_packet.buf);
        }

        if (held_line != NULL)
        {
            lineUnlock(held_line);
        }
    }
}

static void synfinsnitrickRunHoldTimeout(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;

    tunnel_t                      *t       = arg1;
    line_t                        *l       = arg2;
    synfinsnitrick_hold_timeout_t *context = arg3;

    synfinsnitrickReleaseTimedOutHold(t, &context->key, context->generation);
    memoryFree(context);
    lineUnlock(l);
}

static void synfinsnitrickCleanupHoldTimeout(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    memoryFree(arg3);
    lineUnlock((line_t *) arg2);
}

static void synfinsnitrickScheduleHoldTimeout(tunnel_t *t, line_t *l, const ipmanipulator_flow_key_t *key,
                                              uint64_t generation, uint32_t delay_ms)
{
    /* Configuration rejects zero; keep direct/internal state fail-open too. */
    delay_ms = max(delay_ms, 1U);

    synfinsnitrick_hold_timeout_t *context = memoryAllocate(sizeof(*context));
    if (context == NULL)
    {
        synfinsnitrickReleaseTimedOutHold(t, key, generation);
        return;
    }

    *context = (synfinsnitrick_hold_timeout_t) {
        .key        = *key,
        .generation = generation,
    };

    /* The queued message owns a separate reference from the held flow record. */
    lineLock(l);
#ifdef IPMANIPULATOR_SYNFIN_TEST_HOOKS
    ipmanipulatorSynfinTestScheduleTimed(lineGetWID(l),
                                         (WorkerMessageCallback) synfinsnitrickRunHoldTimeout,
                                         synfinsnitrickCleanupHoldTimeout,
                                         delay_ms,
                                         t,
                                         l,
                                         context);
#else
    sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                      (WorkerMessageCallback) synfinsnitrickRunHoldTimeout,
                                      synfinsnitrickCleanupHoldTimeout,
                                      delay_ms,
                                      t,
                                      l,
                                      context);
#endif
}

static sbuf_t *synfinsnitrickGenerateTlsClientHello(tunnel_t *t, line_t *l)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    return tlsclientTunnelGenerateClientHello(state->trick_synfin_sni_tls_client_tunnel,
                                              l,
                                              (const uint8_t *) state->trick_synfin_sni_value,
                                              state->trick_synfin_sni_value_len);
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

static sbuf_t *synfinsnitrickBuildGeneratedTlsDataPacket(line_t *l, const ipmanipulator_captured_packet_t *held_packet,
                                                         const synfinsnitrick_tcp_packet_info_t *held_info,
                                                         uint32_t payload_len, uint32_t seq, uint16_t ip_identification,
                                                         uint8_t tcp_flags)
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
                                                         uint32_t generated_payload_len, uint32_t real_payload_len,
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
                                                const ipmanipulator_captured_packet_t  *held_packet,
                                                const ipmanipulator_tstate_t           *state,
                                                const synfinsnitrick_tcp_packet_info_t *held_info,
                                                uint16_t ip_identification, uint32_t *syn_seq_out)
{
    synfinsnitrick_tcp_packet_info_t        syn_template_info = {0};
    sbuf_t                                 *source_template   = NULL;
    const synfinsnitrick_tcp_packet_info_t *source_info       = NULL;

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

    synfinsnitrickFinalizePacketChecksum(
        syn_packet, source_info->ip_header_len, state->trick_synfin_sni_random_syn_checksum);

    return syn_packet;
}

static sbuf_t *synfinsnitrickBuildFakeClosePacket(line_t *l, const ipmanipulator_captured_packet_t *held_packet,
                                                  const ipmanipulator_tstate_t           *state,
                                                  const synfinsnitrick_tcp_packet_info_t *held_info,
                                                  uint32_t control_seq, uint16_t ip_identification)
{
    if (l == NULL || held_packet == NULL || held_packet->buf == NULL || held_info == NULL || state == NULL)
    {
        return NULL;
    }

    uint8_t control_flags = state->trick_synfin_sni_use_rst ? (TCP_RST | TCP_ACK) : (TCP_FIN | TCP_ACK);
    sbuf_t *packet        = synfinsnitrickBuildPacketFromTemplate(
        l, held_packet->buf, held_info, NULL, 0, control_seq, ip_identification, control_flags);
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

    synfinsnitrickFinalizePacketChecksum(packet, held_info->ip_header_len, state->trick_synfin_sni_random_fin_checksum);
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

static bool synfinsnitrickBuildPacketSequence(tunnel_t *t, line_t *l, const sbuf_t *syn_packet_template,
                                              const ipmanipulator_captured_packet_t  *held_packet,
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

    sbuf_t *packet_fin = synfinsnitrickBuildFakeClosePacket(l, held_packet, state, held_info, close_seq, next_ip_id++);
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
        sbuf_t *generated_tail =
            synfinsnitrickBuildGeneratedTlsDataPacket(l,
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

    lineSetRecalculateChecksum(l, recalculate_checksum);
    ipmanipulatorEmitUpstream(t, l, buf, tunnelNextUpStreamPayload);
    return lineIsAlive(l);
}

static bool synfinsnitrickSendUpstreamDirect(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    return synfinsnitrickSendUpstreamDirectWithMode(t, l, buf, true);
}

static void synfinsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    /* Stateful-SNI validation forbids same-instance packet duplication. */
    discard synfinsnitrickSendUpstreamDirect(t, l, buf);
}

static void synfinsnitrickRecycleOutput(line_t *l, sbuf_t *buf)
{
#ifdef IPMANIPULATOR_SYNFIN_TEST_HOOKS
    if (synfinsnitrick_test_recycle_hook != NULL)
    {
        synfinsnitrick_test_recycle_hook(buf);
    }
#endif

    lineReuseBuffer(l, buf);
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

        /*
         * The synchronous loop already fixes the order of the crafted sequence,
         * so no pacing is applied here. A forwarded packet may close the line,
         * which is why `alive` gates every later packet into recycling instead.
         */
        if (alive)
        {
            alive = synfinsnitrickSendUpstreamDirectWithMode(t, l, packet, false);
        }
        else
        {
            synfinsnitrickRecycleOutput(l, packet);
        }

        sequence->packets[i] = NULL;
    }

    sequence->count = 0;
    lineUnlock(l);
}

#ifdef IPMANIPULATOR_SYNFIN_TEST_HOOKS
void ipmanipulatorSynfinTestSetRecycleHook(synfinsnitrick_test_recycle_hook_t hook)
{
    synfinsnitrick_test_recycle_hook = hook;
}

void ipmanipulatorSynfinTestSendOutputs(tunnel_t *t, line_t *l, sbuf_t **packets, uint16_t count)
{
    assert(count <= kSynfinSniMaxEmittedPackets);

    synfinsnitrick_packet_sequence_t sequence = {.count = count};
    for (uint16_t i = 0; i < count; ++i)
    {
        sequence.packets[i] = packets[i];
        packets[i]          = NULL;
    }

    synfinsnitrickSendOutputs(t, l, &sequence);
}
#endif

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
                                         const synfinsnitrick_tcp_packet_info_t *current_info, bool *block_flow_out)
{
    ipmanipulator_tstate_t          *state     = tunnelGetState(t);
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

    sbuf_t *combined_packet =
        synfinsnitrickBuildCombinedPacket(held_packet->line, held_packet, &held_info, current_info);
    if (combined_packet == NULL)
    {
        synfinsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *generated_hello = synfinsnitrickGenerateTlsClientHello(t, l);
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

    uint32_t additional_payload_len = synfinsnitrickChooseAdditionalPayloadLen(
        state, generated_payload_len, real_payload_len, real_sni_payload_offset);
    uint32_t packet_y_payload_len = generated_payload_len + additional_payload_len;

    synfinsnitrick_packet_sequence_t sequence = {0};
    const uint8_t *combined_payload  = (const uint8_t *) sbufGetRawPtr(combined_packet) + held_info.headers_len;
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

/* Runs under the shard lock: dispose only, never forward or call the tunnel. */
static void synfinsnitrickDestroyFlowRecord(void *record, void *context)
{
    discard context;

    synfinsnitrickDestroyFlow((ipmanipulator_synfin_flow_t *) record);
}

bool synfinsnitrickInitializeState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    return ipmanipulatorFlowTableInit(&state->synfin_table,
                                      "synfin-sni",
                                      state->trick_stateful_flow_limit,
                                      (uint32_t) getTotalWorkersCount(),
                                      sizeof(ipmanipulator_synfin_flow_t),
                                      synfinsnitrickDestroyFlowRecord,
                                      NULL);
}

void synfinsnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    ipmanipulatorFlowTableDestroy(&state->synfin_table);
}

bool synfinsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));

    ipmanipulator_tstate_t          *state  = tunnelGetState(t);
    synfinsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                         now_ms = getTickMS();

    if (! synfinsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_captured_packet_t held_packet         = {0};
    bool                            bypass_current      = false;
    sbuf_t                         *syn_packet_template = NULL;

    ipmanipulator_flow_key_t    key   = synfinsnitrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = synfinsnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        return false;
    }

    bool                        opening_syn = synfinsnitrickIsPureSyn(&info);
    ipmanipulator_flow_entry_t *entry       = ipmanipulatorFlowShardFind(&state->synfin_table, shard, &key);

    if (entry != NULL && opening_syn)
    {
        synfinsnitrickInitializeFlow(synfinsnitrickEntryRecord(entry), &info, buf, now_ms);
    }
    else if (entry != NULL && ! synfinsnitrickFlowIsForward(synfinsnitrickEntryRecord(entry), &info))
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

        entry = synfinsnitrickReserveLocked(state, shard, &key, &info, buf, now_ms);
    }

    if (entry == NULL)
    {
        ipmanipulatorFlowShardUnlock(shard);
        LOGW("IpManipulator: synfin-sni could not admit a flow record; the packet passes unchanged");
        return false;
    }

    ipmanipulator_synfin_flow_t *flow = synfinsnitrickEntryRecord(entry);

    synfinsnitrickTouchLocked(shard, entry, now_ms);

    if (flow->phase == kIpManipulatorSynfinFlowPhaseBlocked)
    {
        if (synfinsnitrickHasFinOrRst(&info))
        {
            ipmanipulatorFlowShardRemove(&state->synfin_table, shard, entry);
        }

        ipmanipulatorFlowShardUnlock(shard);
        lineReuseBuffer(l, buf);
        return true;
    }

    if (synfinsnitrickHasFinOrRst(&info))
    {
        if (flow->phase == kIpManipulatorSynfinFlowPhaseHoldThird)
        {
            bypass_current = synfinsnitrickTakeHeldPacketLocked(flow, &held_packet);
        }

        ipmanipulatorFlowShardRemove(&state->synfin_table, shard, entry);
        ipmanipulatorFlowShardUnlock(shard);

        if (! bypass_current)
        {
            return false;
        }

        line_t *held_line = held_packet.line;
        synfinsnitrickSendHeldThenCurrentNormal(t, &held_packet, l, buf);
        if (held_line != NULL)
        {
            lineUnlock(held_line);
        }
        return true;
    }

    switch (flow->phase)
    {
    case kIpManipulatorSynfinFlowPhaseWarmup:
        if (flow->warmup_packets_seen < kSynfinSniWarmupPackets)
        {
            flow->warmup_packets_seen += 1;
            ipmanipulatorFlowShardUnlock(shard);

            synfinsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        if (info.tcp_payload_len == 0)
        {
            flow->phase = kIpManipulatorSynfinFlowPhasePassthrough;
            ipmanipulatorFlowShardUnlock(shard);

            synfinsnitrickSendNormalNow(t, l, buf);
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
            flow->phase = kIpManipulatorSynfinFlowPhasePassthrough;
            ipmanipulatorFlowShardUnlock(shard);

            synfinsnitrickSendNormalNow(t, l, buf);
            return true;
        }

        flow->phase            = kIpManipulatorSynfinFlowPhaseHoldThird;
        flow->held_packet      = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
        flow->hold_generation  = ipmanipulatorAllocateFlowGeneration(state);
        flow->hold_timer_armed = true;

        uint64_t hold_generation = flow->hold_generation;

        /* The flow record retains the packet line until the hold is detached. */
        lineLock(l);
        ipmanipulatorFlowShardUnlock(shard);

        synfinsnitrickScheduleHoldTimeout(t, l, &key, hold_generation, state->trick_synfin_sni_hold_timeout_ms);
        return true;

    case kIpManipulatorSynfinFlowPhasePassthrough:
        ipmanipulatorFlowShardUnlock(shard);
        synfinsnitrickSendNormalNow(t, l, buf);
        return true;

    case kIpManipulatorSynfinFlowPhaseHoldThird: {
        bool block_flow = false;

        discard synfinsnitrickTakeHeldPacketLocked(flow, &held_packet);

        line_t *held_line = held_packet.line;

        /*
         * Take ownership of the SYN template: the entry pointer does not survive
         * the unlock below, and the crafted transcript is the template's last
         * user on this generation.
         */
        syn_packet_template       = flow->syn_packet_template;
        flow->syn_packet_template = NULL;

        ipmanipulatorFlowShardUnlock(shard);

        bool handled = synfinsnitrickHandleHeldPair(t, l, &held_packet, syn_packet_template, buf, &info, &block_flow);

        if (held_line != NULL)
        {
            lineUnlock(held_line);
        }

        synfinsnitrickDestroyStandalonePacket(&syn_packet_template);

        shard = ipmanipulatorFlowTableLockShard(&state->synfin_table, &key);
        if (shard != NULL)
        {
            entry = synfinsnitrickFindLocked(state, shard, &key, &info);
            if (entry != NULL)
            {
                synfinsnitrickFinalizeFlowLocked(synfinsnitrickEntryRecord(entry), block_flow);
                synfinsnitrickTouchLocked(shard, entry, getTickMS());
            }
            ipmanipulatorFlowShardUnlock(shard);
        }

        return handled;
    }

    case kIpManipulatorSynfinFlowPhaseBlocked:
    default:
        ipmanipulatorFlowShardUnlock(shard);
        break;
    }

    return false;
}
