#include "trick.h"

#include "loggers/network_logger.h"

enum
{
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
    uint64_t generation;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t next_delay_ms;
    uint16_t src_port;
    uint16_t dst_port;
    /* 0 releases original packet 1; 1 releases originals 2 through N in order. */
    uint8_t release_phase;
    wid_t   wid;
} echsnitrick_delayed_release_t;

typedef struct echsnitrick_flow_identity_s
{
    uint64_t                 generation;
    ipmanipulator_flow_key_t key;
    uint32_t                 src_addr;
    uint32_t                 dst_addr;
    uint16_t                 src_port;
    uint16_t                 dst_port;
} echsnitrick_flow_identity_t;

enum
{
    kEchSniReleasePhaseFirst = 0,
    kEchSniReleasePhaseRest  = 1
};

#ifdef IPMANIPULATOR_ECHSNI_TEST_HOOKS
bool ipmanipulatorEchSniTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                          WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                          void *arg2, void *arg3);
void ipmanipulatorEchSniTestBeforeFakeSend(tunnel_t *t);
#endif

/* ---------------------------------------------------------------- packets -- */

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

static void echsnitrickDestroyStandalonePacket(sbuf_t **packet)
{
    if (packet == NULL || *packet == NULL)
    {
        return;
    }

    sbufDestroy(*packet);
    *packet = NULL;
}

static bool echsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                          echsnitrick_tcp_packet_info_t *info)
{
    ipv4_packet_view_t packet_view = {0};
    if (info == NULL || ! ipv4packetviewParseTcp(packet, packet_length, &packet_view) || packet_view.fragmented)
    {
        return false;
    }

    *info = (echsnitrick_tcp_packet_info_t) {
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

static bool echsnitrickIsPureSyn(const echsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && ipmanipulatorIsFlowOpeningSyn(info->tcp_flags, info->tcp_payload_len);
}

static bool echsnitrickHasFinOrRst(const echsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && (info->tcp_flags & (TCP_FIN | TCP_RST)) != 0;
}

/* --------------------------------------------------------------- records -- */

static void echsnitrickReleasePendingOriginalsLocked(ipmanipulator_echsni_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    for (uint8_t i = 0; i < flow->pending_original_count; ++i)
    {
        echsnitrickDestroyCapturedPacket(&flow->pending_original_packets[i]);
    }

    flow->pending_original_count = 0;
    flow->next_release_index     = 0;
    flow->shard1_release_at_ms   = 0;
    flow->shard2_release_at_ms   = 0;
}

static uint8_t echsnitrickTakePendingOriginalsLocked(ipmanipulator_echsni_flow_t     *flow,
                                                     ipmanipulator_captured_packet_t *out, uint8_t capacity)
{
    if (flow == NULL || out == NULL || capacity == 0)
    {
        return 0;
    }

    assert(flow->next_release_index <= flow->pending_original_count);
    const uint8_t remaining = (uint8_t) (flow->pending_original_count - flow->next_release_index);
    assert(capacity >= remaining);
    const uint8_t take_capacity = min(capacity, remaining);

    uint8_t count = 0;
    for (uint8_t i = flow->next_release_index; i < flow->pending_original_count && count < take_capacity; ++i)
    {
        out[count++]                      = flow->pending_original_packets[i];
        flow->pending_original_packets[i] = (ipmanipulator_captured_packet_t) {0};
    }

    /* Keep release builds leak-free if a future caller supplies a short array. */
    for (uint8_t i = (uint8_t) (flow->next_release_index + count); i < flow->pending_original_count; ++i)
    {
        echsnitrickDestroyCapturedPacket(&flow->pending_original_packets[i]);
    }

    flow->pending_original_count = 0;
    flow->next_release_index     = 0;
    flow->shard1_release_at_ms   = 0;
    flow->shard2_release_at_ms   = 0;
    return count;
}

static void echsnitrickDestroyFlow(ipmanipulator_echsni_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    echsnitrickReleasePendingOriginalsLocked(flow);
    memoryZero(flow, sizeof(*flow));
}

/* Runs under the shard lock: dispose only, never forward or call the tunnel. */
static void echsnitrickDestroyFlowRecord(void *record, void *context)
{
    discard context;

    echsnitrickDestroyFlow((ipmanipulator_echsni_flow_t *) record);
}

static ipmanipulator_echsni_flow_t *echsnitrickEntryRecord(ipmanipulator_flow_entry_t *entry)
{
    return (ipmanipulator_echsni_flow_t *) ipmanipulatorFlowEntryRecord(entry);
}

static ipmanipulator_flow_key_t echsnitrickMakeKey(const echsnitrick_tcp_packet_info_t *info)
{
    return ipmanipulatorFlowKeyMake(info->src_addr, info->src_port, info->dst_addr, info->dst_port);
}

/* The record keeps the client-to-server orientation the transcript logic uses. */
static bool echsnitrickFlowIsForward(const ipmanipulator_echsni_flow_t *flow, const echsnitrick_tcp_packet_info_t *info)
{
    return flow->src_addr == info->src_addr && flow->dst_addr == info->dst_addr && flow->src_port == info->src_port &&
           flow->dst_port == info->dst_port;
}

static uint64_t echsnitrickNextGeneration(ipmanipulator_tstate_t *state)
{
    uint64_t generation = atomicIncU64(&state->echsni_next_generation) + 1U;

    if (generation == 0)
    {
        generation = atomicIncU64(&state->echsni_next_generation) + 1U;
    }

    return generation;
}

static void echsnitrickInitializeFlow(ipmanipulator_tstate_t *state, ipmanipulator_echsni_flow_t *flow,
                                      const echsnitrick_tcp_packet_info_t *info, uint64_t now_ms)
{
    echsnitrickDestroyFlow(flow);

    *flow = (ipmanipulator_echsni_flow_t) {
        .created_ms       = now_ms,
        .last_activity_ms = now_ms,
        .generation       = echsnitrickNextGeneration(state),
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .phase            = kIpManipulatorEchSniFlowPhaseAwaitingClientHello,
    };
}

static echsnitrick_flow_identity_t echsnitrickGetFlowIdentity(const ipmanipulator_echsni_flow_t *flow)
{
    return (echsnitrick_flow_identity_t) {
        .generation = flow->generation,
        .key        = ipmanipulatorFlowKeyMake(flow->src_addr, flow->src_port, flow->dst_addr, flow->dst_port),
        .src_addr   = flow->src_addr,
        .dst_addr   = flow->dst_addr,
        .src_port   = flow->src_port,
        .dst_port   = flow->dst_port,
    };
}

static ipmanipulator_flow_shard_t *echsnitrickLockShard(ipmanipulator_tstate_t         *state,
                                                        const ipmanipulator_flow_key_t *key, uint64_t now_ms)
{
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, key);

    if (shard != NULL)
    {
        discard ipmanipulatorFlowShardExpire(&state->echsni_table, shard, now_ms, kIpManipulatorFlowCleanupBudget);
    }

    return shard;
}

static void echsnitrickTouchLocked(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                   uint64_t now_ms)
{
    ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

    flow->last_activity_ms = now_ms;
    ipmanipulatorFlowShardTouch(shard,
                                entry,
                                flow->phase == kIpManipulatorEchSniFlowPhaseReleasing
                                    ? flow->shard2_release_at_ms + kEchSniIdleTimeoutMs
                                    : now_ms + kEchSniIdleTimeoutMs);
}

/*
 * Resolves an identity (normalized tuple plus generation) to its entry. The
 * returned pointer is only valid while the shard stays locked.
 */
static ipmanipulator_flow_entry_t *echsnitrickFindByIdentityLocked(ipmanipulator_tstate_t            *state,
                                                                   ipmanipulator_flow_shard_t        *shard,
                                                                   const echsnitrick_flow_identity_t *identity)
{
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->echsni_table, shard, &identity->key);

    if (entry == NULL)
    {
        return NULL;
    }

    const ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

    if (flow->generation != identity->generation || flow->src_addr != identity->src_addr ||
        flow->src_port != identity->src_port)
    {
        return NULL;
    }

    return entry;
}

/* ------------------------------------------------------------- forwarding -- */

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

    lineSetRecalculateChecksum(l, true);
    ipmanipulatorEmitUpstream(t, l, buf, tunnelNextUpStreamPayload);
    return lineIsAlive(l);
}

static void echsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard echsnitrickSendUpstreamDirect(t, l, buf);
}

/* --------------------------------------------------- ClientHello parsing -- */

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

    /* Never let untrusted binary bytes reach a log format string. */
    for (size_t i = 0; i < copy_len; ++i)
    {
        if (dst[i] < 0x20 || dst[i] > 0x7E)
        {
            dst[i] = '?';
        }
    }
}

/*
 * Bounded candidate parsing for the embedded inner ClientHello.
 *
 * A structurally TLS-looking byte run is not enough: every candidate must parse
 * as a complete ClientHello record through parseTlsRecordSni() and must carry
 * exactly the configured ech-sni-trick host name. Zero matches, a truncated or
 * malformed candidate, a different host name, or more than one match all fail
 * open.
 */
static bool echsnitrickFindInnerClientHello(const ipmanipulator_tstate_t *state, const uint8_t *packet,
                                            uint32_t packet_length, const echsnitrick_clienthello_match_t *match,
                                            uint32_t *inner_offset_out, uint32_t *inner_len_out)
{
    if (state == NULL || packet == NULL || match == NULL || inner_offset_out == NULL || inner_len_out == NULL ||
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
    uint32_t       matches     = 0;
    uint32_t       best_offset = 0;
    uint32_t       best_len    = 0;

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

        sni_match_t inner = {0};
        if (! parseTlsRecordSni(tls, tls_total_len, &inner))
        {
            continue;
        }

        if (inner.sni_name_len != state->trick_ech_sni_value_len)
        {
            continue;
        }

        if (memoryCompare(tls + inner.sni_name_offset, state->trick_ech_sni_value, inner.sni_name_len) != 0)
        {
            continue;
        }

        matches += 1U;
        if (matches > 1U)
        {
            LOGW("IpManipulator: ech-sni-trick rejected flow because the ECH payload contains more than one inner "
                 "ClientHello matching the configured host name");
            return false;
        }

        best_offset = match->ech_payload_offset + offset;
        best_len    = tls_total_len;
    }

    if (matches != 1U)
    {
        return false;
    }

    *inner_offset_out = best_offset;
    *inner_len_out    = best_len;
    return true;
}

/* ------------------------------------------------------- packet crafting -- */

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

static uint8_t echsnitrickGetContinuationPushFlags(uint8_t original_flags)
{
    return (uint8_t) ((original_flags & kEchSniContinuationPreserveFlags) | TCP_PSH);
}

/*
 * Picks the captured packet whose payload range contains payload_offset so the
 * fake inner packet inherits a real data-packet header template.
 */
static bool echsnitrickSelectTemplateForOffset(const ipmanipulator_tls_capture_slot_t *slot, uint32_t payload_offset,
                                               sbuf_t **template_buf, echsnitrick_tcp_packet_info_t *template_info)
{
    uint32_t consumed = 0;

    for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
    {
        sbuf_t                       *buf  = slot->captured_packets[i].buf;
        echsnitrick_tcp_packet_info_t info = {0};

        if (buf == NULL ||
            ! echsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
        {
            return false;
        }

        if (payload_offset < consumed + info.tcp_payload_len || i + 1U == slot->captured_packets_count)
        {
            *template_buf  = buf;
            *template_info = info;
            return true;
        }

        consumed += info.tcp_payload_len;
    }

    return false;
}

/* ------------------------------------------------------- delayed release -- */

static bool echsnitrickScheduleOriginalRelease(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                               uint8_t release_phase, uint32_t delay_ms, uint32_t next_delay_ms);
static void echsnitrickDrainPendingOriginals(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                             uint8_t release_phase, uint32_t next_delay_ms);

/*
 * Takes the one original this release phase owns next. Detaching a single packet
 * per shard-lock acquisition keeps every later packet cancellable by a close that
 * lands while the earlier ones are still being emitted.
 */
static bool echsnitrickTakeNextReleasePacket(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                             uint8_t release_phase, ipmanipulator_captured_packet_t *out,
                                             bool *schedule_next)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    bool                    taken = false;

    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &identity->key);
    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = echsnitrickFindByIdentityLocked(state, shard, identity);
    if (entry != NULL)
    {
        ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

        if (flow->phase == kIpManipulatorEchSniFlowPhaseReleasing)
        {
            uint8_t first = release_phase == kEchSniReleasePhaseFirst ? 0U : 1U;
            uint8_t last  = release_phase == kEchSniReleasePhaseFirst ? 1U : flow->pending_original_count;
            uint8_t index = flow->next_release_index;

            if (index >= first && index < last && index < flow->pending_original_count)
            {
                *out                                  = flow->pending_original_packets[index];
                flow->pending_original_packets[index] = (ipmanipulator_captured_packet_t) {0};
                flow->next_release_index              = (uint8_t) (index + 1U);
                *schedule_next = release_phase == kEchSniReleasePhaseFirst && flow->pending_original_count > 1U;
                taken          = true;

                if (flow->next_release_index >= flow->pending_original_count)
                {
                    flow->phase                  = kIpManipulatorEchSniFlowPhasePassthrough;
                    flow->pending_original_count = 0;
                    flow->next_release_index     = 0;
                    flow->shard1_release_at_ms   = 0;
                    flow->shard2_release_at_ms   = 0;
                    flow->last_activity_ms       = getTickMS();
                    ipmanipulatorFlowShardTouch(shard, entry, flow->last_activity_ms + kEchSniIdleTimeoutMs);
                }
            }
        }
    }

    ipmanipulatorFlowShardUnlock(shard);
    return taken;
}

static void echsnitrickDrainPendingOriginals(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                             uint8_t release_phase, uint32_t next_delay_ms)
{
    if (t == NULL || identity == NULL)
    {
        return;
    }

    bool alive         = true;
    bool schedule_next = false;
    bool emitted_any   = false;

    for (uint8_t i = 0; i < kIpManipulatorTlsCaptureMaxPackets; ++i)
    {
        ipmanipulator_captured_packet_t packet = {0};

        if (! echsnitrickTakeNextReleasePacket(t, identity, release_phase, &packet, &schedule_next))
        {
            break;
        }

        if (! lineIsOnCurrentEventWorker(packet.line))
        {
            echsnitrickDestroyCapturedPacket(&packet);
            LOGF("IpManipulator: ech-sni-trick original release ran on the wrong worker");
            abortProgramNow(1);
        }

        emitted_any = true;

        if (alive)
        {
            alive = echsnitrickSendUpstreamDirect(t, packet.line, packet.buf);
        }
        else
        {
            lineReuseBuffer(packet.line, packet.buf);
        }

        packet.line = NULL;
        packet.buf  = NULL;
    }

    if (emitted_any && alive && schedule_next)
    {
        if (! echsnitrickScheduleOriginalRelease(t, identity, kEchSniReleasePhaseRest, next_delay_ms, 0))
        {
            echsnitrickDrainPendingOriginals(t, identity, kEchSniReleasePhaseRest, 0);
        }
    }
}

static void echsnitrickRunDelayedOriginalRelease(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;

    tunnel_t                      *t       = arg1;
    echsnitrick_delayed_release_t *release = arg3;

    if (t == NULL || release == NULL)
    {
        memoryFree(release);
        return;
    }

    echsnitrick_flow_identity_t identity = {
        .generation = release->generation,
        .key = ipmanipulatorFlowKeyMake(release->src_addr, release->src_port, release->dst_addr, release->dst_port),
        .src_addr = release->src_addr,
        .dst_addr = release->dst_addr,
        .src_port = release->src_port,
        .dst_port = release->dst_port,
    };
    uint8_t  release_phase = release->release_phase;
    uint32_t next_delay_ms = release->next_delay_ms;

    memoryFree(release);
    echsnitrickDrainPendingOriginals(t, &identity, release_phase, next_delay_ms);
}

static void echsnitrickCleanupDelayedOriginalRelease(void *arg1, void *arg2, void *arg3)
{
    discard arg2;

    tunnel_t                      *t       = arg1;
    echsnitrick_delayed_release_t *release = arg3;

    if (currentThreadIsEventWorkerWID(release->wid))
    {
        echsnitrick_flow_identity_t identity = {
            .generation = release->generation,
            .key = ipmanipulatorFlowKeyMake(release->src_addr, release->src_port, release->dst_addr, release->dst_port),
            .src_addr = release->src_addr,
            .dst_addr = release->dst_addr,
            .src_port = release->src_port,
            .dst_port = release->dst_port,
        };

        echsnitrickDrainPendingOriginals(t, &identity, release->release_phase, 0);
    }
    memoryFree(release);
}

/* Reads the worker that still owns the next pending original for this phase. */
static bool echsnitrickGetPendingReleaseWorker(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                               uint8_t release_phase, wid_t *wid)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    bool                    found = false;

    if (t == NULL || identity == NULL || wid == NULL)
    {
        return false;
    }

    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &identity->key);
    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = echsnitrickFindByIdentityLocked(state, shard, identity);
    if (entry != NULL)
    {
        const ipmanipulator_echsni_flow_t *flow  = echsnitrickEntryRecord(entry);
        uint8_t                            first = release_phase == kEchSniReleasePhaseFirst ? 0U : 1U;

        if (flow->phase == kIpManipulatorEchSniFlowPhaseReleasing && flow->next_release_index == first &&
            first < flow->pending_original_count && flow->pending_original_packets[first].line != NULL &&
            flow->pending_original_packets[first].buf != NULL)
        {
            *wid  = lineGetWID(flow->pending_original_packets[first].line);
            found = true;
        }
    }

    ipmanipulatorFlowShardUnlock(shard);
    return found;
}

/* Confirms the generation still owns its pending originals before anything is emitted. */
static bool echsnitrickGenerationIsReleasing(tunnel_t *t, const echsnitrick_flow_identity_t *identity)
{
    ipmanipulator_tstate_t     *state     = tunnelGetState(t);
    bool                        releasing = false;
    ipmanipulator_flow_shard_t *shard     = ipmanipulatorFlowTableLockShard(&state->echsni_table, &identity->key);

    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = echsnitrickFindByIdentityLocked(state, shard, identity);

    if (entry != NULL)
    {
        releasing = echsnitrickEntryRecord(entry)->phase == kIpManipulatorEchSniFlowPhaseReleasing;
    }

    ipmanipulatorFlowShardUnlock(shard);
    return releasing;
}

static bool echsnitrickScheduleOriginalRelease(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                               uint8_t release_phase, uint32_t delay_ms, uint32_t next_delay_ms)
{
    wid_t wid = 0;

    if (! echsnitrickGetPendingReleaseWorker(t, identity, release_phase, &wid))
    {
        return true;
    }

    echsnitrick_delayed_release_t *release = memoryAllocate(sizeof(*release));
    if (release == NULL)
    {
        return false;
    }

    *release = (echsnitrick_delayed_release_t) {
        .generation    = identity->generation,
        .src_addr      = identity->src_addr,
        .dst_addr      = identity->dst_addr,
        .next_delay_ms = next_delay_ms,
        .src_port      = identity->src_port,
        .dst_port      = identity->dst_port,
        .release_phase = release_phase,
        .wid           = wid,
    };

    if (delay_ms == 0 && currentThreadIsEventWorkerWID(wid))
    {
        echsnitrickRunDelayedOriginalRelease(NULL, t, NULL, release);
        return true;
    }

#ifdef IPMANIPULATOR_ECHSNI_TEST_HOOKS
    return ipmanipulatorEchSniTestScheduleTimed(wid,
                                                (WorkerMessageCallback) echsnitrickRunDelayedOriginalRelease,
                                                echsnitrickCleanupDelayedOriginalRelease,
                                                delay_ms,
                                                t,
                                                NULL,
                                                release);
#else
    return sendWorkerMessageTimedWithCleanup(wid,
                                             (WorkerMessageCallback) echsnitrickRunDelayedOriginalRelease,
                                             echsnitrickCleanupDelayedOriginalRelease,
                                             delay_ms,
                                             t,
                                             NULL,
                                             release);
#endif
}

/* ------------------------------------------------------------- reporting -- */

static void echsnitrickLogReject(const char *reason, const char *sni_name)
{
    LOGW("IpManipulator: ech-sni-trick failed open for SNI \"%s\" because %s", sni_name, reason);
}

/* ------------------------------------------------- completed-capture path -- */

/*
 * Moves every captured original into the flow's pending batch and finalizes the
 * generation. Returns false when the flow was replaced or closed while the
 * assembled ClientHello was being parsed, in which case the slot is untouched
 * and the caller releases it through the safe fail-open path.
 */
static bool echsnitrickInstallPendingOriginals(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                               ipmanipulator_tls_capture_slot_t *slot, uint64_t now_ms)
{
    ipmanipulator_tstate_t     *state     = tunnelGetState(t);
    ipmanipulator_flow_shard_t *shard     = ipmanipulatorFlowTableLockShard(&state->echsni_table, &identity->key);
    bool                        installed = false;

    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = echsnitrickFindByIdentityLocked(state, shard, identity);
    if (entry != NULL)
    {
        ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

        /*
         * A one-packet ClientHello completes without ever entering Capturing,
         * so both still-eligible phases may install a batch.
         */
        bool eligible = flow->phase == kIpManipulatorEchSniFlowPhaseCapturing ||
                        flow->phase == kIpManipulatorEchSniFlowPhaseAwaitingClientHello;

        if (eligible && flow->pending_original_count == 0)
        {
            for (uint8_t i = 0; i < slot->captured_packets_count; ++i)
            {
                flow->pending_original_packets[i] = slot->captured_packets[i];
                slot->captured_packets[i]         = (ipmanipulator_captured_packet_t) {0};
            }

            flow->pending_original_count = slot->captured_packets_count;
            flow->next_release_index     = 0;
            flow->phase                  = kIpManipulatorEchSniFlowPhaseReleasing;
            flow->last_activity_ms       = now_ms;
            flow->shard1_release_at_ms   = now_ms + state->trick_ech_sni_shard1_delay_ms;
            flow->shard2_release_at_ms   = flow->shard1_release_at_ms + state->trick_ech_sni_shard2_delay_ms;

            slot->captured_packets_count = 0;
            installed                    = true;

            /* Timers own the originals; a watchdog still bounds the record if one is lost. */
            ipmanipulatorFlowShardTouch(shard, entry, flow->shard2_release_at_ms + kEchSniIdleTimeoutMs);
        }
    }

    ipmanipulatorFlowShardUnlock(shard);
    return installed;
}

/* Marks a generation passthrough without disturbing a replacement generation. */
static void echsnitrickMarkPassthrough(tunnel_t *t, const echsnitrick_flow_identity_t *identity, bool block_flow)
{
    ipmanipulator_tstate_t     *state = tunnelGetState(t);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &identity->key);

    if (shard == NULL)
    {
        return;
    }

    ipmanipulator_flow_entry_t *entry = echsnitrickFindByIdentityLocked(state, shard, identity);
    if (entry != NULL)
    {
        ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

        if (flow->phase != kIpManipulatorEchSniFlowPhaseReleasing)
        {
            flow->phase = block_flow ? kIpManipulatorEchSniFlowPhaseBlocked : kIpManipulatorEchSniFlowPhasePassthrough;
        }
    }

    ipmanipulatorFlowShardUnlock(shard);
}

void echsnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                   uint16_t dst_port, uint64_t generation)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    if (state == NULL || generation == 0 || ! ipmanipulatorFlowTableIsReady(&state->echsni_table))
    {
        return;
    }

    echsnitrick_flow_identity_t identity = {
        .generation = generation,
        .key        = ipmanipulatorFlowKeyMake(src_addr, src_port, dst_addr, dst_port),
        .src_addr   = src_addr,
        .dst_addr   = dst_addr,
        .src_port   = src_port,
        .dst_port   = dst_port,
    };

    echsnitrickMarkPassthrough(t, &identity, false);
}

/*
 * Parses one complete captured ClientHello and, when everything checks out,
 * emits the fake inner packet ahead of the untouched originals.
 *
 * On every rejection the captured originals leave unchanged and in sequence
 * order through ipmanipulatorReleaseCapturedPacketsNormal(), which also marks
 * this generation passthrough.
 */
static void echsnitrickProcessCompletedCapture(tunnel_t *t, const echsnitrick_flow_identity_t *identity,
                                               ipmanipulator_tls_capture_slot_t *slot)
{
    ipmanipulator_tstate_t *state  = tunnelGetState(t);
    uint64_t                now_ms = getTickMS();
    char                    sni_name[kIpManipulatorMaxTlsHostNameLen + 1];

    const uint8_t *assembled     = (const uint8_t *) sbufGetRawPtr(slot->assembled_packet);
    uint32_t       assembled_len = sbufGetLength(slot->assembled_packet);

    echsnitrick_clienthello_match_t        match        = {0};
    echsnitrick_clienthello_parse_status_e parse_status = echsnitrickParseClientHello(assembled, assembled_len, &match);

    memoryZero(sni_name, sizeof(sni_name));

    if (parse_status != kEchSniClientHelloParseReady)
    {
        echsnitrickLogReject(parse_status == kEchSniClientHelloParseNoSni
                                 ? "the assembled TLS ClientHello has no usable SNI extension"
                                 : "the assembled TLS ClientHello is malformed or unparseable",
                             "");
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    echsnitrickCopySniName(assembled, &match, sni_name, sizeof(sni_name));

    if (! match.has_ech)
    {
        echsnitrickLogReject("the TLS ClientHello does not contain the encrypted_client_hello extension", sni_name);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    uint32_t inner_offset = 0;
    uint32_t inner_len    = 0;
    if (! echsnitrickFindInnerClientHello(state, assembled, assembled_len, &match, &inner_offset, &inner_len))
    {
        echsnitrickLogReject("the ECH payload holds no single inner ClientHello carrying the configured host name",
                             sni_name);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    uint32_t total_payload_len   = slot->captured_payload_len;
    uint32_t inner_stream_offset = inner_offset - slot->headers_len;

    if (inner_offset < slot->headers_len || inner_stream_offset >= total_payload_len ||
        inner_len > total_payload_len - inner_stream_offset)
    {
        echsnitrickLogReject("the inner ClientHello does not lie inside the captured TCP stream bytes", sni_name);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    sbuf_t                       *template_buf  = NULL;
    echsnitrick_tcp_packet_info_t template_info = {0};
    if (! echsnitrickSelectTemplateForOffset(slot, inner_stream_offset, &template_buf, &template_info))
    {
        echsnitrickLogReject("no captured data packet could serve as a header template", sni_name);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    uint32_t packet_len = (uint32_t) template_info.headers_len + inner_len;
    if (packet_len > GLOBAL_MTU_SIZE)
    {
        LOGW("IpManipulator: ech-sni-trick failed open because the fake inner ClientHello for \"%s\" is %u bytes and "
             "would create a %u-byte TCP packet, exceeding GLOBAL_MTU_SIZE %u",
             sni_name,
             inner_len,
             packet_len,
             GLOBAL_MTU_SIZE);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    /*
     * The fake inner packet is emitted out of order, so its TCP sequence is the
     * exact stream offset of the embedded inner ClientHello.
     */
    echsnitrick_tcp_packet_info_t first_info = {0};
    if (slot->captured_packets[0].buf == NULL ||
        ! echsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(slot->captured_packets[0].buf),
                                        sbufGetLength(slot->captured_packets[0].buf),
                                        &first_info))
    {
        echsnitrickLogReject("the first captured packet is no longer parseable", sni_name);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    line_t *line = slot->captured_packets[0].line;
    sbuf_t *inner_packet =
        echsnitrickBuildPacketFromTemplate(line,
                                           template_buf,
                                           &template_info,
                                           assembled + slot->headers_len + inner_stream_offset,
                                           inner_len,
                                           first_info.seq + inner_stream_offset,
                                           template_info.ip_identification,
                                           echsnitrickGetContinuationPushFlags(template_info.tcp_flags));

    if (inner_packet == NULL)
    {
        echsnitrickLogReject("the fake inner ClientHello packet could not be allocated", sni_name);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    uint8_t original_count = slot->captured_packets_count;

    /* The assembled copy is never forwarded; only originals enter delayed ownership. */
    if (! echsnitrickInstallPendingOriginals(t, identity, slot, now_ms))
    {
        echsnitrickDestroyStandalonePacket(&inner_packet);
        ipmanipulatorReleaseCapturedPacketsNormal(t, slot);
        return;
    }

    echsnitrickDestroyStandalonePacket(&slot->assembled_packet);
    slot->active = false;

    LOGD("IpManipulator: ech-sni-trick sent a fake inner ClientHello for \"%s\" out of order using the existing ECH "
         "payload bytes (inner_stream_offset=%u inner_len=%u originals=%u shard1_delay=%u shard2_delay=%u)",
         sni_name,
         inner_stream_offset,
         inner_len,
         (unsigned int) original_count,
         state->trick_ech_sni_shard1_delay_ms,
         state->trick_ech_sni_shard2_delay_ms);

#ifdef IPMANIPULATOR_ECHSNI_TEST_HOOKS
    ipmanipulatorEchSniTestBeforeFakeSend(t);
#endif

    if (! echsnitrickGenerationIsReleasing(t, identity))
    {
        /* A concurrent close destroyed the originals through the record destructor. */
        echsnitrickDestroyStandalonePacket(&inner_packet);
        LOGD("IpManipulator: ech-sni-trick dropped the fake inner ClientHello because the generation closed");
        return;
    }

    discard echsnitrickSendUpstreamDirect(t, line, inner_packet);

    /* Emission may re-enter the chain, so revalidate before arming the timer. */
    if (! echsnitrickScheduleOriginalRelease(t,
                                             identity,
                                             kEchSniReleasePhaseFirst,
                                             state->trick_ech_sni_shard1_delay_ms,
                                             state->trick_ech_sni_shard2_delay_ms))
    {
        echsnitrickDrainPendingOriginals(t, identity, kEchSniReleasePhaseFirst, 0);
    }
}

/* ------------------------------------------------- capture cancel/release -- */

static void echsnitrickReleaseCaptureNormally(tunnel_t *t, const echsnitrick_flow_identity_t *identity)
{
    ipmanipulator_tls_capture_slot_t slot = {0};

    if (ipmanipulatorTakeMatchingCaptureSlot(t,
                                             identity->src_addr,
                                             identity->dst_addr,
                                             identity->src_port,
                                             identity->dst_port,
                                             kIpManipulatorTlsCaptureKindEchSni,
                                             identity->generation,
                                             false,
                                             &slot))
    {
        ipmanipulatorReleaseCapturedPacketsNormal(t, &slot);
    }
}

static void echsnitrickDisposeCapture(tunnel_t *t, const echsnitrick_flow_identity_t *identity)
{
    ipmanipulator_tls_capture_slot_t slot = {0};

    if (ipmanipulatorTakeMatchingCaptureSlot(t,
                                             identity->src_addr,
                                             identity->dst_addr,
                                             identity->src_port,
                                             identity->dst_port,
                                             kIpManipulatorTlsCaptureKindEchSni,
                                             identity->generation,
                                             false,
                                             &slot))
    {
        ipmanipulatorRecycleCapturedTlsPackets(t, &slot);
    }
}

/* -------------------------------------------------------- release window -- */

/*
 * While originals are pending, only an exact retransmission of a still-pending
 * segment may be swallowed. Anything the trick cannot classify exactly -- a
 * partial overlap, later data, an ACK -- passes through untouched.
 */
static bool echsnitrickIsPendingRetransmitLocked(const ipmanipulator_echsni_flow_t   *flow,
                                                 const echsnitrick_tcp_packet_info_t *info)
{
    if (info->tcp_payload_len == 0)
    {
        return false;
    }

    for (uint8_t i = flow->next_release_index; i < flow->pending_original_count; ++i)
    {
        const ipmanipulator_captured_packet_t *pending      = &flow->pending_original_packets[i];
        echsnitrick_tcp_packet_info_t          pending_info = {0};

        if (pending->buf == NULL || ! echsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(pending->buf),
                                                                    sbufGetLength(pending->buf),
                                                                    &pending_info))
        {
            continue;
        }

        if (pending_info.seq != info->seq || pending_info.tcp_payload_len != info->tcp_payload_len)
        {
            continue;
        }

        if (memoryCompare(pending_info.packet + pending_info.payload_offset,
                          info->packet + info->payload_offset,
                          info->tcp_payload_len) == 0)
        {
            return true;
        }
    }

    return false;
}

/* ------------------------------------------------------------- lifecycle -- */

bool echsnitrickInitializeState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    return ipmanipulatorFlowTableInit(&state->echsni_table,
                                      "ech-sni-trick",
                                      state->trick_stateful_flow_limit,
                                      (uint32_t) getTotalWorkersCount(),
                                      sizeof(ipmanipulator_echsni_flow_t),
                                      echsnitrickDestroyFlowRecord,
                                      NULL);
}

void echsnitrickDestroyState(tunnel_t *t)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    ipmanipulatorFlowTableDestroy(&state->echsni_table);
}

/* ------------------------------------------------------------ downstream -- */

bool echsnitrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));

    discard l;

    ipmanipulator_tstate_t       *state  = tunnelGetState(t);
    echsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                      now_ms = getTickMS();

    if (! echsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_flow_key_t    key   = echsnitrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = echsnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        return false;
    }

    echsnitrick_flow_identity_t identity       = {0};
    bool                        cancel_capture = false;

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->echsni_table, shard, &key);
    if (entry != NULL && echsnitrickFlowIsForward(echsnitrickEntryRecord(entry), &info))
    {
        /* Downstream traffic runs the reverse orientation of the stored record. */
        entry = NULL;
    }

    if (entry != NULL)
    {
        ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

        echsnitrickTouchLocked(shard, entry, now_ms);

        if (echsnitrickHasFinOrRst(&info))
        {
            identity       = echsnitrickGetFlowIdentity(flow);
            cancel_capture = flow->phase == kIpManipulatorEchSniFlowPhaseCapturing;
            ipmanipulatorFlowShardRemove(&state->echsni_table, shard, entry);
        }
    }

    ipmanipulatorFlowShardUnlock(shard);

    if (cancel_capture)
    {
        echsnitrickDisposeCapture(t, &identity);
    }

    return false;
}

/* -------------------------------------------------------------- upstream -- */

bool echsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentEventWorker(l));

    ipmanipulator_tstate_t       *state  = tunnelGetState(t);
    echsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                      now_ms = getTickMS();

    if (! echsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_flow_key_t    key   = echsnitrickMakeKey(&info);
    ipmanipulator_flow_shard_t *shard = echsnitrickLockShard(state, &key, now_ms);

    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->echsni_table, shard, &key);

    /*
     * A valid plain or ECN SYN always starts a fresh generation. Any capture and
     * any pending originals of the previous generation are invalidated first so
     * an old timer or capture can never act on the replacement.
     */
    if (echsnitrickIsPureSyn(&info))
    {
        echsnitrick_flow_identity_t previous         = {0};
        bool                        dispose_previous = false;

        if (entry != NULL)
        {
            ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

            previous         = echsnitrickGetFlowIdentity(flow);
            dispose_previous = true;
            echsnitrickInitializeFlow(state, flow, &info, now_ms);
            echsnitrickTouchLocked(shard, entry, now_ms);
        }
        else
        {
            entry =
                ipmanipulatorFlowShardReserve(&state->echsni_table, shard, &key, now_ms, now_ms + kEchSniIdleTimeoutMs);

            if (entry != NULL)
            {
                echsnitrickInitializeFlow(state, echsnitrickEntryRecord(entry), &info, now_ms);
            }
        }

        bool admitted = entry != NULL;

        ipmanipulatorFlowShardUnlock(shard);

        if (dispose_previous)
        {
            echsnitrickDisposeCapture(t, &previous);
        }

        if (! admitted)
        {
            LOGW("IpManipulator: ech-sni-trick could not admit a flow record; the handshake passes unchanged");
        }

        echsnitrickSendNormalNow(t, l, buf);
        return true;
    }

    if (entry != NULL && ! echsnitrickFlowIsForward(echsnitrickEntryRecord(entry), &info))
    {
        entry = NULL;
    }

    if (entry == NULL)
    {
        ipmanipulatorFlowShardUnlock(shard);
        return false;
    }

    ipmanipulator_echsni_flow_t *flow = echsnitrickEntryRecord(entry);

    echsnitrickTouchLocked(shard, entry, now_ms);

    if (echsnitrickHasFinOrRst(&info))
    {
        echsnitrick_flow_identity_t     identity      = echsnitrickGetFlowIdentity(flow);
        bool                            flush_capture = flow->phase == kIpManipulatorEchSniFlowPhaseCapturing;
        bool                            graceful      = (info.tcp_flags & TCP_RST) == 0;
        ipmanipulator_captured_packet_t pending[kIpManipulatorTlsCaptureMaxPackets];
        uint8_t                         pending_count = 0;

        memoryZero(pending, sizeof(pending));

        /*
         * A graceful close must follow every byte before it. Detach the pending
         * originals here so the record destructor cannot discard them; an RST
         * keeps discarding, because sequence continuity is meaningless after one.
         */
        if (graceful && flow->phase == kIpManipulatorEchSniFlowPhaseReleasing)
        {
            pending_count = echsnitrickTakePendingOriginalsLocked(flow, pending, (uint8_t) ARRAY_SIZE(pending));
        }

        ipmanipulatorFlowShardRemove(&state->echsni_table, shard, entry);
        ipmanipulatorFlowShardUnlock(shard);

        if (flush_capture)
        {
            /* Held originals leave in sequence order before the close packet. */
            echsnitrickReleaseCaptureNormally(t, &identity);
        }

        bool alive = true;
        for (uint8_t i = 0; i < pending_count; ++i)
        {
            ipmanipulator_captured_packet_t *packet = &pending[i];

            if (packet->line == NULL)
            {
                if (packet->buf != NULL)
                {
                    sbufDestroy(packet->buf);
                }
            }
            else if (packet->buf != NULL)
            {
                assert(lineIsOnCurrentEventWorker(packet->line));
                if (alive)
                {
                    alive = echsnitrickSendUpstreamDirect(t, packet->line, packet->buf);
                }
                else
                {
                    lineReuseBuffer(packet->line, packet->buf);
                }
            }

            packet->line = NULL;
            packet->buf  = NULL;
        }

        return false;
    }

    switch (flow->phase)
    {
    case kIpManipulatorEchSniFlowPhaseBlocked:
        ipmanipulatorFlowShardUnlock(shard);
        lineReuseBuffer(l, buf);
        return true;

    case kIpManipulatorEchSniFlowPhasePassthrough:
        ipmanipulatorFlowShardUnlock(shard);
        echsnitrickSendNormalNow(t, l, buf);
        return true;

    case kIpManipulatorEchSniFlowPhaseReleasing: {
        bool swallow = echsnitrickIsPendingRetransmitLocked(flow, &info);

        ipmanipulatorFlowShardUnlock(shard);

        if (swallow)
        {
            LOGD("IpManipulator: ech-sni-trick swallowed an exact retransmission of a still-pending original seq=%u "
                 "payload=%u",
                 info.seq,
                 (unsigned int) info.tcp_payload_len);
            lineReuseBuffer(l, buf);
            return true;
        }

        echsnitrickSendNormalNow(t, l, buf);
        return true;
    }

    case kIpManipulatorEchSniFlowPhaseAwaitingClientHello:
    case kIpManipulatorEchSniFlowPhaseCapturing:
    default:
        break;
    }

    /*
     * Payload-free packets never count as ClientHello segments and must not move
     * the generation out of capture.
     */
    if (info.tcp_payload_len == 0)
    {
        ipmanipulatorFlowShardUnlock(shard);
        echsnitrickSendNormalNow(t, l, buf);
        return true;
    }

    echsnitrick_flow_identity_t identity = echsnitrickGetFlowIdentity(flow);

    ipmanipulatorFlowShardUnlock(shard);

    ipmanipulator_tls_capture_slot_t   slot   = {0};
    ipmanipulator_tls_capture_status_e status = ipmanipulatorCaptureTlsClientHelloForOwner(
        t, l, buf, kIpManipulatorTlsCaptureKindEchSni, identity.generation, &slot);

    switch (status)
    {
    case kIpManipulatorTlsCaptureStatusPending: {
        /* Capture in progress: the helper owns the packet. */
        ipmanipulator_flow_shard_t *pending_shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &key);
        bool                        pending_generation_is_live = false;

        if (pending_shard != NULL)
        {
            ipmanipulator_flow_entry_t *pending_entry =
                echsnitrickFindByIdentityLocked(state, pending_shard, &identity);

            if (pending_entry != NULL)
            {
                echsnitrickEntryRecord(pending_entry)->phase = kIpManipulatorEchSniFlowPhaseCapturing;
                pending_generation_is_live                   = true;
            }

            ipmanipulatorFlowShardUnlock(pending_shard);
        }

        if (! pending_generation_is_live)
        {
            /* A concurrent close/replacement won after capture admission. */
            echsnitrickDisposeCapture(t, &identity);
        }

        return true;
    }

    case kIpManipulatorTlsCaptureStatusReady:
        echsnitrickProcessCompletedCapture(t, &identity, &slot);
        return true;

    case kIpManipulatorTlsCaptureStatusBypassed:
        /* The helper already released the old capture and forwarded this packet. */
        echsnitrickMarkPassthrough(t, &identity, false);
        return true;

    case kIpManipulatorTlsCaptureStatusMiss:
    default:
        echsnitrickMarkPassthrough(t, &identity, false);
        echsnitrickSendNormalNow(t, l, buf);
        return true;
    }
}
