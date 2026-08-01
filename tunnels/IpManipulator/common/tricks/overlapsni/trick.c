#include "trick.h"

#include "crafted_server_hello_bytes.h"
#include "loggers/network_logger.h"

api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message);

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
} overlapsnitrick_tcp_packet_info_t;

typedef struct overlapsnitrick_packet_sequence_s
{
    sbuf_t *packets[kOverlapSniMaxEmittedPackets];
    uint8_t count;
} overlapsnitrick_packet_sequence_t;

typedef struct overlapsnitrick_handle_result_s
{
    bool     block_flow;
    bool     start_delay_window;
    bool     set_downstream_marker;
    uint32_t expected_downstream_seq;
    uint16_t expected_downstream_ip_total_len;
    uint16_t expected_downstream_fingerprint;
} overlapsnitrick_handle_result_t;

static sbuf_t *overlapsnitrickDuplicateStandalonePacket(const sbuf_t *source)
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

static void overlapsnitrickDestroyStandalonePacket(sbuf_t **packet)
{
    if (packet == NULL || *packet == NULL)
    {
        return;
    }

    sbufDestroy(*packet);
    *packet = NULL;
}

static void overlapsnitrickResetFlow(ipmanipulator_overlap_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    memoryZero(flow, sizeof(*flow));
}

static void overlapsnitrickDestroyFlow(ipmanipulator_overlap_flow_t *flow)
{
    if (flow == NULL)
    {
        return;
    }

    overlapsnitrickDestroyCapturedPacket(&flow->held_packet);
    overlapsnitrickDestroyStandalonePacket(&flow->synack_packet);
    overlapsnitrickResetFlow(flow);
}

static void overlapsnitrickInitializeFlow(ipmanipulator_overlap_flow_t            *flow,
                                          const overlapsnitrick_tcp_packet_info_t *info, uint64_t now_ms)
{
    if (flow == NULL || info == NULL)
    {
        return;
    }

    overlapsnitrickDestroyCapturedPacket(&flow->held_packet);
    overlapsnitrickDestroyStandalonePacket(&flow->synack_packet);
    overlapsnitrickResetFlow(flow);

    *flow = (ipmanipulator_overlap_flow_t) {
        .created_ms       = now_ms,
        .last_activity_ms = now_ms,
        .src_addr         = info->src_addr,
        .dst_addr         = info->dst_addr,
        .src_port         = info->src_port,
        .dst_port         = info->dst_port,
        .phase            = kIpManipulatorOverlapFlowPhaseWarmup,
    };
}

static void overlapsnitrickFinalizeFlowLocked(ipmanipulator_overlap_flow_t *flow, bool block_flow,
                                              const overlapsnitrick_handle_result_t *result, uint64_t now_ms)
{
    if (flow == NULL)
    {
        return;
    }

    overlapsnitrickDestroyCapturedPacket(&flow->held_packet);
    overlapsnitrickDestroyStandalonePacket(&flow->synack_packet);
    flow->warmup_packets_seen = kOverlapSniWarmupPackets;
    flow->phase = block_flow ? kIpManipulatorOverlapFlowPhaseBlocked : kIpManipulatorOverlapFlowPhasePassthrough;
    flow->delay_window_until_ms =
        (result != NULL && result->start_delay_window && ! block_flow) ? now_ms + kOverlapSniDelayWindowMs : 0;
    flow->ignore_expected_downstream_packet = result != NULL && result->set_downstream_marker;
    flow->expected_downstream_seq           = result != NULL ? result->expected_downstream_seq : 0;
    flow->expected_downstream_ip_total_len  = result != NULL ? result->expected_downstream_ip_total_len : 0;
    flow->expected_downstream_fingerprint   = result != NULL ? result->expected_downstream_fingerprint : 0;
}

static bool overlapsnitrickParseTcpPacketInfo(const uint8_t *packet, uint32_t packet_length,
                                              overlapsnitrick_tcp_packet_info_t *info)
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

    *info = (overlapsnitrick_tcp_packet_info_t) {
        .packet            = packet,
        .seq               = lwip_ntohl(tcp_header->seqno),
        .ack               = lwip_ntohl(tcp_header->ackno),
        .payload_offset    = headers_len,
        .ip_total_len      = ip_total_len,
        .ip_header_len     = ip_header_len,
        .tcp_header_len    = tcp_header_len,
        .headers_len       = headers_len,
        .tcp_payload_len   = (uint16_t) (ip_total_len - headers_len),
        .src_port          = lwip_ntohs(tcp_header->src),
        .dst_port          = lwip_ntohs(tcp_header->dest),
        .ip_identification = lwip_ntohs(IPH_ID(ipheader)),
        .src_addr          = ipheader->src.addr,
        .dst_addr          = ipheader->dest.addr,
        .tcp_flags         = TCPH_FLAGS(tcp_header),
    };

    return true;
}

static bool overlapsnitrickIsPureSyn(const overlapsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && ipmanipulatorIsFlowOpeningSyn(info->tcp_flags, info->tcp_payload_len);
}

static bool overlapsnitrickIsSynAck(const overlapsnitrick_tcp_packet_info_t *info)
{
    return info != NULL && info->tcp_payload_len == 0 &&
           (info->tcp_flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) &&
           (info->tcp_flags & (TCP_FIN | TCP_RST)) == 0;
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

static sbuf_t *overlapsnitrickAllocateRequestBuffer(uint32_t len)
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

static sbuf_t *overlapsnitrickGenerateTlsClientHello(tunnel_t *t)
{
    static const char kGenerateTlsHelloPrefix[] = "generateTlsHello:";

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    uint32_t request_len = (uint32_t) (sizeof(kGenerateTlsHelloPrefix) - 1) + state->trick_overlap_sni_value_len;
    sbuf_t  *request_buf = overlapsnitrickAllocateRequestBuffer(request_len);

    if (request_buf == NULL)
    {
        return NULL;
    }

    sbufSetLength(request_buf, request_len);
    memoryCopy(sbufGetMutablePtr(request_buf), kGenerateTlsHelloPrefix, sizeof(kGenerateTlsHelloPrefix) - 1);
    memoryCopy(sbufGetMutablePtr(request_buf) + (sizeof(kGenerateTlsHelloPrefix) - 1),
               state->trick_overlap_sni_value,
               state->trick_overlap_sni_value_len);

    api_result_t result = tlsclientTunnelApi(state->trick_overlap_sni_tls_client_tunnel, request_buf);

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

static uint16_t overlapsnitrickFingerprintPacket(const uint8_t *packet, uint16_t packet_len)
{
    return calcGenericChecksum(packet, packet_len, 0);
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

static sbuf_t *overlapsnitrickBuildCraftedServerHelloPacket(line_t *l, sbuf_t *synack_packet,
                                                            const overlapsnitrick_tcp_packet_info_t *synack_info,
                                                            uint32_t client_ack, uint32_t *server_seq_out,
                                                            uint16_t *packet_len_out, uint16_t *fingerprint_out)
{
    if (l == NULL || synack_packet == NULL || synack_info == NULL || server_seq_out == NULL || packet_len_out == NULL ||
        fingerprint_out == NULL)
    {
        return NULL;
    }

    if (GLOBAL_MTU_SIZE <= synack_info->headers_len)
    {
        return NULL;
    }

    uint32_t payload_len = min((uint32_t) kOverlapSniCraftedServerHelloBytesLen,
                               (uint32_t) GLOBAL_MTU_SIZE - (uint32_t) synack_info->headers_len);
    uint32_t packet_len  = (uint32_t) synack_info->headers_len + payload_len;

    if (payload_len == 0 || packet_len > UINT16_MAX)
    {
        return NULL;
    }

    sbuf_t *packet_buf = clonePacketWithLength(l, synack_packet, packet_len);
    if (packet_buf == NULL)
    {
        return NULL;
    }

    sbufSetLength(packet_buf, packet_len);

    uint8_t *packet     = sbufGetMutablePtr(packet_buf);
    uint32_t server_seq = synack_info->seq + 1U;

    memoryCopyLarge(packet, synack_info->packet, synack_info->headers_len);
    memoryCopyLarge(packet + synack_info->headers_len, kOverlapSniCraftedServerHelloBytes, payload_len);

    struct ip_hdr  *ipheader   = (struct ip_hdr *) packet;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + synack_info->ip_header_len);

    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) packet_len));
    IPH_ID_SET(ipheader, lwip_htons((uint16_t) (synack_info->ip_identification + 1U)));
    IPH_OFFSET_SET(ipheader, lwip_htons((uint16_t) (lwip_ntohs(IPH_OFFSET(ipheader)) & ~(IP_MF | IP_OFFMASK))));
    tcp_header->seqno = lwip_htonl(server_seq);
    tcp_header->ackno = lwip_htonl(client_ack);
    TCPH_FLAGS_SET(tcp_header, TCP_ACK | TCP_PSH);

    calcFullPacketChecksum(packet, packet_len);

    *server_seq_out  = server_seq;
    *packet_len_out  = (uint16_t) packet_len;
    *fingerprint_out = overlapsnitrickFingerprintPacket(packet, (uint16_t) packet_len);
    return packet_buf;
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

static void overlapsnitrickForwardHelperPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    tunnelUpStreamPayload(state->trick_overlap_sni_server_hello_upstream_tunnel, l, buf);
}

static bool overlapsnitrickSendHelperPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (l == NULL || buf == NULL)
    {
        if (buf != NULL)
        {
            sbufDestroy(buf);
        }
        return l != NULL ? lineIsAlive(l) : false;
    }

    if (! lineIsAlive(l))
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    if (state->trick_overlap_sni_server_hello_upstream_tunnel == NULL)
    {
        lineReuseBuffer(l, buf);
        return lineIsAlive(l);
    }

    /*
     * This dedicated branch is built from the captured downstream SYN|ACK and
     * must retain that original tuple. Apply checksum/protocol egress ordering
     * without adding a portghost trailer.
     */
    lineSetRecalculateChecksum(l, true);
    ipmanipulatorEmitUpstreamPreservingTuple(t, l, buf, overlapsnitrickForwardHelperPacket);
    return lineIsAlive(l);
}

static void overlapsnitrickRunDelayedNormal(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;

    tunnel_t *t   = arg1;
    line_t   *l   = arg2;
    sbuf_t   *buf = arg3;

    if (lineIsAlive(l))
    {
        discard overlapsnitrickSendUpstreamDirect(t, l, buf);
    }
    else
    {
        lineReuseBuffer(l, buf);
    }

    lineUnlock(l);
}

static void overlapsnitrickCleanupDelayedBuffer(line_t *l, sbuf_t *buf)
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

static void overlapsnitrickCleanupDelayedNormal(void *arg1, void *arg2, void *arg3)
{
    discard arg1;

    line_t *l   = arg2;
    sbuf_t *buf = arg3;

    overlapsnitrickCleanupDelayedBuffer(l, buf);
    lineUnlock(l);
}

static bool overlapsnitrickScheduleNormalSend(tunnel_t *t, line_t *l, sbuf_t *buf, uint32_t delay_ms)
{
    if (t == NULL || l == NULL || buf == NULL)
    {
        if (l != NULL && buf != NULL)
        {
            lineReuseBuffer(l, buf);
        }
        else if (buf != NULL)
        {
            sbufDestroy(buf);
        }

        return l != NULL ? lineIsAlive(l) : false;
    }

    if (! lineIsAlive(l))
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    if (delay_ms == 0 && getWID() == lineGetWID(l))
    {
        return overlapsnitrickSendUpstreamDirect(t, l, buf);
    }

    lineLock(l);
    sendWorkerMessageTimedWithCleanup(lineGetWID(l),
                                      (WorkerMessageCallback) overlapsnitrickRunDelayedNormal,
                                      overlapsnitrickCleanupDelayedNormal,
                                      delay_ms,
                                      t,
                                      l,
                                      buf);
    return lineIsAlive(l);
}

static void overlapsnitrickSendNormalNow(tunnel_t *t, line_t *l, sbuf_t *buf)
{
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

    lineLock(line);

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

    lineUnlock(line);
}

static void overlapsnitrickSendOutputs(tunnel_t *t, line_t *l, overlapsnitrick_packet_sequence_t *normal_sequence,
                                       sbuf_t *crafted_server_hello, uint32_t delay_ms)
{
    if (l == NULL || normal_sequence == NULL)
    {
        overlapsnitrickDestroyPacketSequence(normal_sequence);
        overlapsnitrickDestroyStandalonePacket(&crafted_server_hello);
        return;
    }

    lineLock(l);

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

    if (crafted_server_hello != NULL)
    {
        if (alive)
        {
            alive = overlapsnitrickSendHelperPacket(t, l, crafted_server_hello);
        }
        else
        {
            lineReuseBuffer(l, crafted_server_hello);
        }

        crafted_server_hello = NULL;
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
            uint32_t packet_delay_ms = delay_ms + ((uint32_t) (i - 2U) * kOverlapSniDelaySequenceSpacingMs);
            alive                    = overlapsnitrickScheduleNormalSend(t, l, packet, packet_delay_ms);
        }
        else
        {
            lineReuseBuffer(l, packet);
        }

        normal_sequence->packets[i] = NULL;
    }

    normal_sequence->count = 0;
    lineUnlock(l);
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
                                          sbuf_t *synack_packet, sbuf_t *current_buf,
                                          const overlapsnitrick_tcp_packet_info_t *current_info,
                                          overlapsnitrick_handle_result_t         *result)
{
    overlapsnitrick_tcp_packet_info_t held_info   = {0};
    overlapsnitrick_tcp_packet_info_t synack_info = {0};
    ipmanipulator_tstate_t           *state       = tunnelGetState(t);

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

        overlapsnitrickDestroyStandalonePacket(&synack_packet);

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
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
        overlapsnitrickSendNormalNow(t, l, current_buf);
        return true;
    }

    if ((uint32_t) current_info->seq != held_info.seq + (uint32_t) held_info.tcp_payload_len ||
        held_info.tcp_payload_len == 0 || current_info->tcp_payload_len == 0)
    {
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *combined_packet =
        overlapsnitrickBuildCombinedPacket(held_packet->line, held_packet, &held_info, current_info);
    if (combined_packet == NULL)
    {
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    sbuf_t *generated_hello = overlapsnitrickGenerateTlsClientHello(t);
    if (generated_hello == NULL)
    {
        sbufDestroy(combined_packet);
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
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
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
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
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
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
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
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
        overlapsnitrickDestroyStandalonePacket(&synack_packet);
        overlapsnitrickSendHeldThenCurrentNormal(t, held_packet, l, current_buf);
        return true;
    }

    if (result != NULL)
    {
        result->start_delay_window = true;
    }

    sbuf_t *crafted_server_hello = NULL;
    if (synack_packet != NULL &&
        overlapsnitrickParseTcpPacketInfo(
            (const uint8_t *) sbufGetRawPtr(synack_packet), sbufGetLength(synack_packet), &synack_info) &&
        overlapsnitrickIsSynAck(&synack_info))
    {
        uint32_t server_seq  = 0;
        uint16_t packet_len  = 0;
        uint16_t fingerprint = 0;
        uint32_t client_ack  = held_info.seq + generated_payload_len;

        crafted_server_hello = overlapsnitrickBuildCraftedServerHelloPacket(
            held_packet->line, synack_packet, &synack_info, client_ack, &server_seq, &packet_len, &fingerprint);

        if (crafted_server_hello != NULL && result != NULL)
        {
            result->set_downstream_marker            = true;
            result->expected_downstream_seq          = server_seq;
            result->expected_downstream_ip_total_len = packet_len;
            result->expected_downstream_fingerprint  = fingerprint;
        }
    }

    reuseBuffer(generated_hello);
    sbufDestroy(combined_packet);
    overlapsnitrickDestroyStandalonePacket(&synack_packet);
    overlapsnitrickRecycleCapturedPacket(held_packet);
    lineReuseBuffer(l, current_buf);

    overlapsnitrickSendOutputs(t, l, &sequence, crafted_server_hello, state->trick_overlap_sni_delay_ms);
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
    assert(lineGetWID(l) == getWID());

    ipmanipulator_tstate_t           *state   = tunnelGetState(t);
    overlapsnitrick_tcp_packet_info_t info    = {0};
    const uint8_t                    *packet  = (const uint8_t *) sbufGetRawPtr(buf);
    uint64_t                          now_ms  = getTickMS();
    bool                              drop_it = false;

    if (! overlapsnitrickParseTcpPacketInfo(packet, sbufGetLength(buf), &info))
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

        if (flow->ignore_expected_downstream_packet && info.ip_total_len == flow->expected_downstream_ip_total_len &&
            info.seq == flow->expected_downstream_seq &&
            overlapsnitrickFingerprintPacket(packet, info.ip_total_len) == flow->expected_downstream_fingerprint)
        {
            flow->ignore_expected_downstream_packet = false;
            flow->expected_downstream_seq           = 0;
            flow->expected_downstream_ip_total_len  = 0;
            flow->expected_downstream_fingerprint   = 0;
            drop_it                                 = true;
        }
        else if (overlapsnitrickHasFinOrRst(&info))
        {
            ipmanipulatorFlowShardRemove(&state->overlap_table, shard, entry);
        }
        else if (flow->synack_packet == NULL && overlapsnitrickIsSynAck(&info))
        {
            flow->synack_packet = overlapsnitrickDuplicateStandalonePacket(buf);
        }
    }

    ipmanipulatorFlowShardUnlock(shard);

    if (! drop_it)
    {
        return false;
    }

    lineReuseBuffer(l, buf);
    return true;
}

bool overlapsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineGetWID(l) == getWID());

    ipmanipulator_tstate_t           *state  = tunnelGetState(t);
    overlapsnitrick_tcp_packet_info_t info   = {0};
    uint64_t                          now_ms = getTickMS();

    if (! overlapsnitrickParseTcpPacketInfo((const uint8_t *) sbufGetRawPtr(buf), sbufGetLength(buf), &info))
    {
        return false;
    }

    ipmanipulator_captured_packet_t held_packet    = {0};
    sbuf_t                         *synack_packet  = NULL;
    bool                            bypass_current = false;

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

    if (overlapsnitrickHasFinOrRst(&info))
    {
        if (flow->phase == kIpManipulatorOverlapFlowPhaseHoldThird)
        {
            held_packet       = flow->held_packet;
            flow->held_packet = (ipmanipulator_captured_packet_t) {0};
            bypass_current    = true;
        }

        ipmanipulatorFlowShardRemove(&state->overlap_table, shard, entry);
        ipmanipulatorFlowShardUnlock(shard);

        if (! bypass_current)
        {
            return false;
        }

        overlapsnitrickSendHeldThenCurrentNormal(t, &held_packet, l, buf);
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

        flow->phase       = kIpManipulatorOverlapFlowPhaseHoldThird;
        flow->held_packet = (ipmanipulator_captured_packet_t) {.line = l, .buf = buf};
        ipmanipulatorFlowShardUnlock(shard);
        return true;

    case kIpManipulatorOverlapFlowPhasePassthrough: {
        bool delay_window_active = now_ms < flow->delay_window_until_ms;
        ipmanipulatorFlowShardUnlock(shard);
        if (delay_window_active)
        {
            discard overlapsnitrickScheduleNormalSend(t, l, buf, state->trick_overlap_sni_delay_ms);
        }
        else
        {
            overlapsnitrickSendNormalNow(t, l, buf);
        }
        return true;
    }

    case kIpManipulatorOverlapFlowPhaseHoldThird: {
        overlapsnitrick_handle_result_t result = {0};

        held_packet         = flow->held_packet;
        synack_packet       = flow->synack_packet;
        flow->held_packet   = (ipmanipulator_captured_packet_t) {0};
        flow->synack_packet = NULL;

        ipmanipulatorFlowShardUnlock(shard);

        bool handled = overlapsnitrickHandleHeldPair(t, l, &held_packet, synack_packet, buf, &info, &result);

        /* The entry pointer did not survive the unlock; resolve the tuple again. */
        shard = ipmanipulatorFlowTableLockShard(&state->overlap_table, &key);
        if (shard != NULL)
        {
            entry = overlapsnitrickFindLocked(state, shard, &key, &info, true);
            if (entry != NULL)
            {
                overlapsnitrickFinalizeFlowLocked(
                    overlapsnitrickEntryRecord(entry), result.block_flow, &result, now_ms);
                overlapsnitrickTouchLocked(shard, entry, getTickMS());
            }
            ipmanipulatorFlowShardUnlock(shard);
        }

        return handled;
    }

    case kIpManipulatorOverlapFlowPhaseBlocked:
    default:
        ipmanipulatorFlowShardUnlock(shard);
        break;
    }

    return false;
}
