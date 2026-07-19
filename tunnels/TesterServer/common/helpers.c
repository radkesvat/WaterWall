#include "structure.h"

#include "loggers/network_logger.h"

static const uint32_t kTesterServerChunkSizes[kTesterServerChunkCount] = {
    1U,
    2U,
    4U,
    32U,
    512U,
    1024U,
    4096U,
    32768U,
    32769U,
    1 * 1024U * 1024U,
    2 * 1024U * 1024U,
};

static const uint32_t kTesterServerPacketChunkSizes[kTesterServerChunkCount] = {
    1U,
    2U,
    4U,
    32U,
    64U,
    128U,
    256U,
    512U,
    1024U,
    kMaxAllowedPacketLength - 1U,
    kMaxAllowedPacketLength,
};

static const uint32_t kTesterServerPacketIpv4ChunkSizes[kTesterServerChunkCount] = {
    21U,
    22U,
    24U,
    52U,
    84U,
    148U,
    276U,
    532U,
    1044U,
    kMaxAllowedPacketLength - 1U,
    kMaxAllowedPacketLength,
};

static const uint32_t kTesterServerPacketIpv4TransportChunkSizes[kTesterServerChunkCount] = {
    41U,
    42U,
    44U,
    52U,
    84U,
    148U,
    276U,
    532U,
    1044U,
    kMaxAllowedPacketLength - 1U,
    kMaxAllowedPacketLength,
};

enum
{
    kTesterServerPacketIpv4RequestSourcePort = 40123,
    kTesterServerPacketIpv4RequestDestPort   = 40234
};

static inline uint16_t testerserverPacketIpv4HeaderLength(void)
{
    return (uint16_t) sizeof(struct ip_hdr);
}

static uint16_t testerserverPacketIpv4TransportHeaderLength(const testerserver_tstate_t *ts)
{
    switch (ts->packet_ipv4_transport)
    {
    case kTesterServerPacketIpv4TransportTcp:
        return (uint16_t) sizeof(struct tcp_hdr);
    case kTesterServerPacketIpv4TransportUdp:
        return (uint16_t) sizeof(struct udp_hdr);
    case kTesterServerPacketIpv4TransportIcmp:
        return (uint16_t) sizeof(struct icmp_echo_hdr);
    default:
        return 0;
    }
}

static uint16_t testerserverPacketIpv4PayloadOffset(const testerserver_tstate_t *ts)
{
    return testerserverPacketIpv4HeaderLength() + testerserverPacketIpv4TransportHeaderLength(ts);
}

static inline const uint32_t *testerserverGetChunkTable(tunnel_t *t)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (! ts->packet_mode)
    {
        return kTesterServerChunkSizes;
    }

    if (ts->packet_ipv4_mode && ts->packet_ipv4_transport != kTesterServerPacketIpv4TransportNone)
    {
        return kTesterServerPacketIpv4TransportChunkSizes;
    }

    return ts->packet_ipv4_mode ? kTesterServerPacketIpv4ChunkSizes : kTesterServerPacketChunkSizes;
}

static uint8_t testerserverFlowMarker(uint8_t flow_id, testerserver_direction_e direction)
{
    return (uint8_t) (flow_id ^ ((direction == kTesterServerDirectionResponse) ? 0xC3U : 0x3CU));
}

static uint8_t testerserverPatternByte(uint32_t offset, uint8_t chunk_index, uint8_t flow_id,
                                       testerserver_direction_e direction)
{
    // The first request byte encodes the client-selected flow id so this chain end
    // can verify and mirror the sequence independently of its local worker id.
    if (chunk_index == 0 && offset == 0)
    {
        return testerserverFlowMarker(flow_id, direction);
    }

    uint32_t value = offset;
    value ^= value >> 13;
    value *= 0x45d9f3bu;
    value ^= ((uint32_t) chunk_index + 1U) * 0x27d4eb2du;
    value ^= ((uint32_t) flow_id + 1U) * 0x165667b1u;
    value ^= (direction == kTesterServerDirectionResponse) ? 0xA5A5A5A5u : 0x5A5A5A5Au;
    value ^= value >> 16;
    return (uint8_t) value;
}

static uint8_t testerserverDecodeFlowId(uint8_t marker, testerserver_direction_e direction)
{
    return (uint8_t) (marker ^ ((direction == kTesterServerDirectionResponse) ? 0xC3U : 0x3CU));
}

static uint8_t testerserverGetFlowId(tunnel_t *t, line_t *l)
{
    testerserver_lstate_t *ls = lineGetState(l, t);

    return ls->flow_id;
}

static void testerserverFillBytesForFlow(uint8_t flow_id, uint8_t *ptr, uint32_t payload_len, uint8_t chunk_index,
                                         uint32_t chunk_offset, testerserver_direction_e direction)
{
    for (uint32_t i = 0; i < payload_len; ++i)
    {
        ptr[i] = testerserverPatternByte(chunk_offset + i, chunk_index, flow_id, direction);
    }
}

static void testerserverFillPayloadForFlow(uint8_t flow_id, sbuf_t *buf, uint8_t chunk_index, uint32_t chunk_offset,
                                           testerserver_direction_e direction)
{
    uint32_t payload_len = sbufGetLength(buf);
    uint8_t *ptr         = sbufGetMutablePtr(buf);

    testerserverFillBytesForFlow(flow_id, ptr, payload_len, chunk_index, chunk_offset, direction);
}

static uint32_t testerserverGetExpectedPayloadLength(tunnel_t *t, uint8_t chunk_index)
{
    testerserver_tstate_t *ts         = tunnelGetState(t);
    uint32_t               chunk_size = testerserverGetChunkSize(t, chunk_index);

    if (! (ts->packet_mode && ts->packet_ipv4_mode))
    {
        return chunk_size;
    }

    return chunk_size - testerserverPacketIpv4PayloadOffset(ts);
}

static void testerserverPacketIpv4DirectionAddrs(const testerserver_tstate_t *ts, testerserver_direction_e direction,
                                                 uint32_t *src_addr, uint32_t *dest_addr)
{
    if (direction == kTesterServerDirectionRequest)
    {
        *src_addr  = ts->packet_ipv4_source_addr;
        *dest_addr = ts->packet_ipv4_dest_addr;
        return;
    }

    *src_addr  = ts->packet_ipv4_dest_addr;
    *dest_addr = ts->packet_ipv4_source_addr;
}

static void testerserverPacketIpv4DirectionPorts(testerserver_direction_e direction, uint16_t *src_port,
                                                 uint16_t *dest_port)
{
    if (direction == kTesterServerDirectionRequest)
    {
        *src_port  = kTesterServerPacketIpv4RequestSourcePort;
        *dest_port = kTesterServerPacketIpv4RequestDestPort;
        return;
    }

    *src_port  = kTesterServerPacketIpv4RequestDestPort;
    *dest_port = kTesterServerPacketIpv4RequestSourcePort;
}

static void testerserverWritePacketIpv4Header(testerserver_tstate_t *ts, sbuf_t *buf,
                                              testerserver_direction_e direction)
{
    uint8_t       *packet     = sbufGetMutablePtr(buf);
    struct ip_hdr *ipheader   = (struct ip_hdr *) packet;
    uint32_t       src_addr   = 0;
    uint32_t       dest_addr  = 0;
    uint16_t       packet_len = (uint16_t) sbufGetLength(buf);
    uint16_t       header_len = testerserverPacketIpv4HeaderLength();
    uint16_t       packet_id  = (uint16_t) (atomicAdd(&ts->packet_ipv4_identification, 1U) + 1U);

    testerserverPacketIpv4DirectionAddrs(ts, direction, &src_addr, &dest_addr);

    memoryZero(packet, header_len);

    IPH_VHL_SET(ipheader, 4, header_len / 4U);
    IPH_TOS_SET(ipheader, 0);
    IPH_LEN_SET(ipheader, lwip_htons(packet_len));
    IPH_ID_SET(ipheader, lwip_htons(packet_id));
    IPH_OFFSET_SET(ipheader, 0);
    IPH_TTL_SET(ipheader, ts->packet_ipv4_ttl);
    IPH_PROTO_SET(ipheader, ts->packet_ipv4_protocol);
    IPH_CHKSUM_SET(ipheader, 0);
    ipheader->src.addr  = src_addr;
    ipheader->dest.addr = dest_addr;
}

static void testerserverWritePacketIpv4Transport(testerserver_tstate_t *ts, sbuf_t *buf, uint8_t chunk_index,
                                                 testerserver_direction_e direction)
{
    uint8_t  *packet        = sbufGetMutablePtr(buf);
    uint8_t  *transport     = packet + testerserverPacketIpv4HeaderLength();
    uint16_t  transport_len = (uint16_t) (sbufGetLength(buf) - testerserverPacketIpv4HeaderLength());
    uint16_t  src_port      = 0;
    uint16_t  dest_port     = 0;

    testerserverPacketIpv4DirectionPorts(direction, &src_port, &dest_port);

    switch (ts->packet_ipv4_transport)
    {
    case kTesterServerPacketIpv4TransportTcp: {
        struct tcp_hdr *tcpheader = (struct tcp_hdr *) transport;

        memoryZero(tcpheader, sizeof(*tcpheader));
        tcpheader->src   = lwip_htons(src_port);
        tcpheader->dest  = lwip_htons(dest_port);
        tcpheader->seqno = lwip_htonl(0x10203040U + (uint32_t) chunk_index);
        tcpheader->ackno = lwip_htonl(0x50607080U + (uint32_t) chunk_index);
        TCPH_HDRLEN_FLAGS_SET(tcpheader, sizeof(*tcpheader) / 4U, TCP_ACK | TCP_PSH);
        tcpheader->wnd  = lwip_htons(64240U);
        tcpheader->urgp = 0;
        return;
    }
    case kTesterServerPacketIpv4TransportUdp: {
        struct udp_hdr *udpheader = (struct udp_hdr *) transport;

        memoryZero(udpheader, sizeof(*udpheader));
        udpheader->src  = lwip_htons(src_port);
        udpheader->dest = lwip_htons(dest_port);
        udpheader->len  = lwip_htons(transport_len);
        return;
    }
    case kTesterServerPacketIpv4TransportIcmp: {
        struct icmp_echo_hdr *icmpheader = (struct icmp_echo_hdr *) transport;

        memoryZero(icmpheader, sizeof(*icmpheader));
        ICMPH_TYPE_SET(icmpheader, direction == kTesterServerDirectionRequest ? ICMP_ECHO : ICMP_ER);
        ICMPH_CODE_SET(icmpheader, 0);
        icmpheader->id    = lwip_htons(0x5151U);
        icmpheader->seqno = lwip_htons(chunk_index);
        return;
    }
    default:
        return;
    }
}

static bool testerserverVerifyPacketIpv4Transport(testerserver_tstate_t *ts, sbuf_t *buf, uint8_t chunk_index,
                                                  testerserver_direction_e direction)
{
    uint8_t       *packet        = sbufGetMutablePtr(buf);
    struct ip_hdr *ipheader      = (struct ip_hdr *) packet;
    uint8_t       *transport     = packet + testerserverPacketIpv4HeaderLength();
    uint16_t       transport_len = (uint16_t) (sbufGetLength(buf) - testerserverPacketIpv4HeaderLength());
    uint16_t       src_port      = 0;
    uint16_t       dest_port     = 0;
    uint16_t       transport_checksum = 0;

    if (ts->packet_ipv4_transport == kTesterServerPacketIpv4TransportNone)
    {
        return true;
    }

    testerserverPacketIpv4DirectionPorts(direction, &src_port, &dest_port);

    switch (ts->packet_ipv4_transport)
    {
    case kTesterServerPacketIpv4TransportTcp: {
        struct tcp_hdr *tcpheader = (struct tcp_hdr *) transport;

        if (transport_len < sizeof(*tcpheader) || tcpheader->src != lwip_htons(src_port) ||
            tcpheader->dest != lwip_htons(dest_port) ||
            TCPH_HDRLEN_BYTES(tcpheader) != sizeof(*tcpheader) ||
            TCPH_FLAGS(tcpheader) != (TCP_ACK | TCP_PSH) ||
            tcpheader->seqno != lwip_htonl(0x10203040U + (uint32_t) chunk_index) ||
            tcpheader->ackno != lwip_htonl(0x50607080U + (uint32_t) chunk_index) ||
            tcpheader->wnd != lwip_htons(64240U) || tcpheader->urgp != 0)
        {
            return false;
        }
        transport_checksum = tcpheader->chksum;
        break;
    }
    case kTesterServerPacketIpv4TransportUdp: {
        struct udp_hdr *udpheader = (struct udp_hdr *) transport;

        if (transport_len < sizeof(*udpheader) || udpheader->src != lwip_htons(src_port) ||
            udpheader->dest != lwip_htons(dest_port) || udpheader->len != lwip_htons(transport_len))
        {
            return false;
        }
        transport_checksum = udpheader->chksum;
        break;
    }
    case kTesterServerPacketIpv4TransportIcmp: {
        struct icmp_echo_hdr *icmpheader = (struct icmp_echo_hdr *) transport;
        uint8_t               expected_type = direction == kTesterServerDirectionRequest ? ICMP_ECHO : ICMP_ER;

        if (transport_len < sizeof(*icmpheader) || icmpheader->type != expected_type || icmpheader->code != 0 ||
            icmpheader->id != lwip_htons(0x5151U) || icmpheader->seqno != lwip_htons(chunk_index))
        {
            return false;
        }
        transport_checksum = icmpheader->chksum;
        break;
    }
    default:
        return false;
    }

    uint16_t ip_checksum = IPH_CHKSUM(ipheader);
    calcFullPacketChecksum(packet);

    if (IPH_CHKSUM(ipheader) != ip_checksum)
    {
        return false;
    }

    switch (ts->packet_ipv4_transport)
    {
    case kTesterServerPacketIpv4TransportTcp:
        return ((struct tcp_hdr *) transport)->chksum == transport_checksum;
    case kTesterServerPacketIpv4TransportUdp:
        return ((struct udp_hdr *) transport)->chksum == transport_checksum;
    case kTesterServerPacketIpv4TransportIcmp:
        return ((struct icmp_echo_hdr *) transport)->chksum == transport_checksum;
    default:
        return false;
    }
}

static bool testerserverDecodePacketIpv4(tunnel_t *t, sbuf_t *buf, testerserver_direction_e direction,
                                         uint8_t chunk_index, uint8_t **payload_ptr, uint32_t *payload_len)
{
    testerserver_tstate_t *ts         = tunnelGetState(t);
    const uint32_t         packet_len = sbufGetLength(buf);
    const uint16_t         header_len = testerserverPacketIpv4HeaderLength();
    const uint16_t         payload_offset = testerserverPacketIpv4PayloadOffset(ts);

    if (packet_len < payload_offset)
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);
    if ((IPH_V(ipheader) != 4) || (IPH_HL_BYTES(ipheader) != header_len))
    {
        return false;
    }

    if ((lwip_ntohs(IPH_OFFSET(ipheader)) != 0) || (IPH_PROTO(ipheader) != ts->packet_ipv4_protocol))
    {
        return false;
    }

    if (lwip_ntohs(IPH_LEN(ipheader)) != packet_len)
    {
        return false;
    }

    uint32_t expected_src  = 0;
    uint32_t expected_dest = 0;
    testerserverPacketIpv4DirectionAddrs(ts, direction, &expected_src, &expected_dest);

    if ((ipheader->src.addr != expected_src) || (ipheader->dest.addr != expected_dest))
    {
        return false;
    }

    if (! testerserverVerifyPacketIpv4Transport(ts, buf, chunk_index, direction))
    {
        return false;
    }

    *payload_ptr = sbufGetMutablePtr(buf) + payload_offset;
    *payload_len = packet_len - payload_offset;
    return true;
}

void testerserverFail(tunnel_t *t, line_t *l, const char *reason)
{
    LOGE("TesterServer: worker %u failed: %s", (unsigned int) lineGetWID(l), reason);
    discard t;
    terminateProgram(1);
}

uint8_t testerserverGetChunkCount(tunnel_t *t)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    assert(ts->chunk_count > 0);
    assert(ts->chunk_count <= kTesterServerChunkCount);
    return ts->chunk_count;
}

uint32_t testerserverGetChunkSize(tunnel_t *t, uint8_t index)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    uint32_t               chunk_size;

    assert(index < testerserverGetChunkCount(t));
    chunk_size = testerserverGetChunkTable(t)[index];

    if (ts->packet_mode && ts->max_payload_size > 0 && chunk_size > ts->max_payload_size)
    {
        chunk_size = ts->max_payload_size;
    }

    return chunk_size;
}

uint64_t testerserverGetRemainingBytes(tunnel_t *t, uint8_t index)
{
    uint64_t remaining = 0;
    const uint32_t *chunk_sizes = testerserverGetChunkTable(t);

    const uint8_t chunk_count = testerserverGetChunkCount(t);

    for (uint8_t i = index; i < chunk_count; ++i)
    {
        remaining += chunk_sizes[i];
    }

    return remaining;
}

sbuf_t *testerserverCreatePayload(tunnel_t *t, line_t *l, uint8_t chunk_index, uint32_t chunk_offset,
                                  uint32_t payload_len, testerserver_direction_e direction)
{
    buffer_pool_t *pool        = lineGetBufferPool(l);
    testerserver_tstate_t *ts  = tunnelGetState(t);
    sbuf_t        *buf         = NULL;

    if (ts->packet_mode)
    {
        if (payload_len != testerserverGetChunkSize(t, chunk_index))
        {
            testerserverFail(t, l, "packet-mode payload generation attempted to split a packet chunk");
            return NULL;
        }

        if (payload_len <= bufferpoolGetSmallBufferSize(pool))
        {
            buf = bufferpoolGetSmallBuffer(pool);
        }
        else
        {
            testerserverFail(t, l, "packet-mode response exceeded small buffer size");
            return NULL;
        }
    }
    else if (payload_len <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (payload_len <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        testerserverFail(t, l, "stream-mode payload generation exceeded large buffer size");
        return NULL;
    }

    sbufSetLength(buf, payload_len);

    if (ts->packet_mode && ts->packet_ipv4_mode)
    {
        const uint16_t payload_offset = testerserverPacketIpv4PayloadOffset(ts);

        if (payload_len <= payload_offset)
        {
            testerserverFail(t, l, "packet-ipv4 chunk size is smaller than the configured packet headers");
            return NULL;
        }

        testerserverWritePacketIpv4Header(ts, buf, direction);
        testerserverWritePacketIpv4Transport(ts, buf, chunk_index, direction);
        testerserverFillBytesForFlow(testerserverGetFlowId(t, l), sbufGetMutablePtr(buf) + payload_offset,
                                     payload_len - payload_offset, chunk_index, chunk_offset, direction);
        calcFullPacketChecksum(sbufGetMutablePtr(buf));
        return buf;
    }

    testerserverFillPayloadForFlow(testerserverGetFlowId(t, l), buf, chunk_index, chunk_offset, direction);

    return buf;
}

bool testerserverVerifyChunk(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t chunk_index, testerserver_direction_e direction,
                             uint32_t *bad_offset, uint8_t *expected, uint8_t *actual)
{
    testerserver_tstate_t *ts          = tunnelGetState(t);
    testerserver_lstate_t *ls          = lineGetState(l, t);
    const uint8_t         *ptr         = sbufGetRawPtr(buf);
    uint32_t               payload_len = sbufGetLength(buf);
    uint8_t                flow_id     = ls->flow_id;

    if (payload_len != testerserverGetChunkSize(t, chunk_index))
    {
        if (bad_offset != NULL)
        {
            *bad_offset = payload_len;
        }
        return false;
    }

    if (ts->packet_mode && ts->packet_ipv4_mode)
    {
        uint8_t *packet_payload = NULL;

        if (! testerserverDecodePacketIpv4(t, buf, direction, chunk_index, &packet_payload, &payload_len))
        {
            if (bad_offset != NULL)
            {
                *bad_offset = 0;
            }
            return false;
        }

        if (payload_len != testerserverGetExpectedPayloadLength(t, chunk_index))
        {
            if (bad_offset != NULL)
            {
                *bad_offset = payload_len;
            }
            return false;
        }

        ptr = packet_payload;
    }

    if (direction == kTesterServerDirectionRequest && chunk_index == 0)
    {
        ls->flow_id = testerserverDecodeFlowId(ptr[0], direction);
        return true;
    }

    for (uint32_t i = 0; i < payload_len; ++i)
    {
        uint8_t expected_byte = testerserverPatternByte(i, chunk_index, flow_id, direction);
        if (ptr[i] != expected_byte)
        {
            if (bad_offset != NULL)
            {
                *bad_offset = i;
            }
            if (expected != NULL)
            {
                *expected = expected_byte;
            }
            if (actual != NULL)
            {
                *actual = ptr[i];
            }
            return false;
        }
    }

    return true;
}

void testerserverHandlePacketRequestPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    testerserver_lstate_t *ls          = lineGetState(l, t);
    uint32_t               bad_offset  = 0;
    uint8_t                expected    = 0;
    uint8_t                actual      = 0;
    uint8_t                chunk_count = testerserverGetChunkCount(t);

    if (ls->request_rx_index >= chunk_count)
    {
        lineReuseBuffer(l, buf);
        testerserverFail(t, l, "received extra packet-mode request payload after verification completed");
        return;
    }

    if (! testerserverVerifyChunk(t, l, buf, ls->request_rx_index, kTesterServerDirectionRequest, &bad_offset,
                                  &expected, &actual))
    {
        LOGE("TesterServer: worker %u packet request chunk %u mismatch (size=%u expected_size=%u bad_offset=%u "
             "expected=0x%02x actual=0x%02x)",
             (unsigned int) lineGetWID(l), (unsigned int) ls->request_rx_index, (unsigned int) sbufGetLength(buf),
             (unsigned int) testerserverGetChunkSize(t, ls->request_rx_index), (unsigned int) bad_offset,
             (unsigned int) expected, (unsigned int) actual);
        lineReuseBuffer(l, buf);
        terminateProgram(1);
        return;
    }

    sbuf_t *response_buf = testerserverCreatePayload(t, l, ls->request_rx_index, 0,
                                                     testerserverGetChunkSize(t, ls->request_rx_index),
                                                     kTesterServerDirectionResponse);

    lineReuseBuffer(l, buf);
    ls->request_rx_index += 1;
    bufferqueuePushBack(&ls->response_queue, response_buf);
    testerserverScheduleResponseSend(t, l, ls);
}

static bool testerserverInferPacketChunkIndex(tunnel_t *t, sbuf_t *buf, uint8_t *chunk_index_out)
{
    const uint8_t  chunk_count = testerserverGetChunkCount(t);
    const uint32_t payload_len = sbufGetLength(buf);

    for (uint8_t i = 0; i < chunk_count; ++i)
    {
        if (payload_len == testerserverGetChunkSize(t, i))
        {
            *chunk_index_out = i;
            return true;
        }
    }

    return false;
}

static bool testerserverVerifyStatelessPacketChunk(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t chunk_index,
                                                   uint32_t *bad_offset, uint8_t *expected, uint8_t *actual)
{
    testerserver_lstate_t *ls = lineGetState(l, t);
    uint8_t                original_flow_id = ls->flow_id;

    if (chunk_index == 0)
    {
        return testerserverVerifyChunk(t, l, buf, chunk_index, kTesterServerDirectionRequest, bad_offset, expected,
                                       actual);
    }

    for (uint16_t flow_id = 0; flow_id < 254U; ++flow_id)
    {
        ls->flow_id = (uint8_t) flow_id;
        if (testerserverVerifyChunk(t, l, buf, chunk_index, kTesterServerDirectionRequest, bad_offset, expected,
                                    actual))
        {
            return true;
        }
    }

    ls->flow_id = original_flow_id;
    return false;
}

void testerserverHandlePacketStatelessRequestPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    testerserver_lstate_t *ls = lineGetState(l, t);
    uint32_t               bad_offset = 0;
    uint8_t                expected = 0;
    uint8_t                actual = 0;
    uint8_t                chunk_index = 0;

    if (! testerserverInferPacketChunkIndex(t, buf, &chunk_index))
    {
        lineReuseBuffer(l, buf);
        testerserverFail(t, l, "received packet-mode stateless request with unexpected packet size");
        return;
    }

    if (! testerserverVerifyStatelessPacketChunk(t, l, buf, chunk_index, &bad_offset, &expected, &actual))
    {
        LOGE("TesterServer: worker %u packet request chunk %u mismatch (size=%u expected_size=%u bad_offset=%u "
             "expected=0x%02x actual=0x%02x)",
             (unsigned int) lineGetWID(l), (unsigned int) chunk_index, (unsigned int) sbufGetLength(buf),
             (unsigned int) testerserverGetChunkSize(t, chunk_index), (unsigned int) bad_offset,
             (unsigned int) expected, (unsigned int) actual);
        lineReuseBuffer(l, buf);
        terminateProgram(1);
        return;
    }

    sbuf_t *response_buf =
        testerserverCreatePayload(t, l, chunk_index, 0, testerserverGetChunkSize(t, chunk_index),
                                  kTesterServerDirectionResponse);

    lineReuseBuffer(l, buf);
    ls->request_rx_index += 1;
    bufferqueuePushBack(&ls->response_queue, response_buf);
    testerserverScheduleResponseSend(t, l, ls);
}

void testerserverScheduleResponseSend(tunnel_t *t, line_t *l, testerserver_lstate_t *ls)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (ls->response_send_scheduled || ls->response_sent)
    {
        return;
    }

    if (ts->packet_mode)
    {
        if (ls->response_paused || bufferqueueGetBufCount(&ls->response_queue) == 0)
        {
            return;
        }
    }
    else
    {
        uint8_t response_limit = ts->streaming_response ? ls->request_rx_index : (ls->response_ready ? testerserverGetChunkCount(t) : 0);

        if (ls->response_paused || ls->response_tx_index >= response_limit)
        {
            return;
        }
    }

    ls->response_send_scheduled = true;
    lineScheduleTask(l, testerserverResponseSendTask, t);
}

void testerserverResponseSendTask(tunnel_t *t, line_t *l)
{
    testerserver_lstate_t *ls = lineGetState(l, t);
    testerserver_tstate_t *ts = tunnelGetState(t);
    buffer_pool_t         *pool = lineGetBufferPool(l);

    ls->response_send_scheduled = false;

    if (ts->packet_mode)
    {
        while (! ls->response_paused && bufferqueueGetBufCount(&ls->response_queue) > 0)
        {
            LineTaskFnWithBuf send_response =
                ls->response_to_next ? tunnelNextUpStreamPayload : tunnelPrevDownStreamPayload;
            sbuf_t *buf = bufferqueuePopFront(&ls->response_queue);

            ls->response_tx_index += 1;
            if (! withLineLockedWithBuf(l, send_response, t, buf))
            {
                LOGF("TesterServer: packet line died during packet-mode response send");
                terminateProgram(1);
                return;
            }
        }

        const uint8_t chunk_count = testerserverGetChunkCount(t);

        if (ls->request_rx_index == chunk_count && ls->response_tx_index == chunk_count &&
            bufferqueueGetBufCount(&ls->response_queue) == 0)
        {
            ls->response_sent = true;
        }

        return;
    }

    const uint8_t chunk_count         = testerserverGetChunkCount(t);
    uint8_t       response_limit      = ts->streaming_response ? ls->request_rx_index : (ls->response_ready ? chunk_count : 0);
    uint32_t      split_payloads_sent = 0;

    while (! ls->response_paused && ls->response_tx_index < response_limit)
    {
        uint32_t chunk_size = testerserverGetChunkSize(t, ls->response_tx_index);
        uint32_t remaining  = chunk_size - ls->response_tx_offset;
        uint32_t max_len    = bufferpoolGetLargeBufferSize(pool);

        if (ts->max_payload_size > 0 && ts->max_payload_size < max_len)
        {
            max_len = ts->max_payload_size;
        }

        if (max_len == 0)
        {
            testerserverFail(t, l, "large buffer pool reports zero writable payload capacity");
            return;
        }

        uint32_t payload_len = (remaining < max_len) ? remaining : max_len;
        sbuf_t *buf = testerserverCreatePayload(t, l, ls->response_tx_index, ls->response_tx_offset, payload_len,
                                                kTesterServerDirectionResponse);

        if (buf == NULL)
        {
            return;
        }

        ls->response_tx_offset += payload_len;
        if (ls->response_tx_offset == chunk_size)
        {
            ls->response_tx_index += 1;
            ls->response_tx_offset = 0;
        }

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
        {
            return;
        }

        if (ts->max_payload_size > 0 && ! ls->response_paused && ls->response_tx_index < response_limit)
        {
            split_payloads_sent += 1;

            if (split_payloads_sent >= ts->split_payload_burst)
            {
                ls->response_send_scheduled = true;
                if (ts->split_payload_delay_ms == 0)
                {
                    lineScheduleTask(l, testerserverResponseSendTask, t);
                }
                else
                {
                    lineScheduleDelayedTask(l, testerserverResponseSendTask, ts->split_payload_delay_ms, t);
                }
                return;
            }
        }
    }

    if (ls->response_tx_index == chunk_count)
    {
        ls->response_sent = true;
    }
}
