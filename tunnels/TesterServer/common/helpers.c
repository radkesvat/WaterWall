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
    1499U,
    1500U,
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
    1499U,
    1500U,
};

static inline uint16_t testerserverPacketIpv4HeaderLength(void)
{
    return (uint16_t) sizeof(struct ip_hdr);
}

static inline const uint32_t *testerserverGetChunkTable(tunnel_t *t)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (! ts->packet_mode)
    {
        return kTesterServerChunkSizes;
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

    return chunk_size - testerserverPacketIpv4HeaderLength();
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

    memorySet(packet, 0, header_len);

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

    calcFullPacketChecksum(packet);
}

static bool testerserverDecodePacketIpv4(tunnel_t *t, sbuf_t *buf, testerserver_direction_e direction,
                                         uint8_t **payload_ptr, uint32_t *payload_len)
{
    testerserver_tstate_t *ts         = tunnelGetState(t);
    const uint32_t         packet_len = sbufGetLength(buf);
    const uint16_t         header_len = testerserverPacketIpv4HeaderLength();

    if (packet_len < header_len)
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

    *payload_ptr = sbufGetMutablePtr(buf) + header_len;
    *payload_len = packet_len - header_len;
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
    assert(index < testerserverGetChunkCount(t));
    return testerserverGetChunkTable(t)[index];
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
        const uint16_t header_len = testerserverPacketIpv4HeaderLength();

        if (payload_len <= header_len)
        {
            testerserverFail(t, l, "packet-ipv4 chunk size is smaller than the IPv4 header");
            return NULL;
        }

        testerserverWritePacketIpv4Header(ts, buf, direction);
        testerserverFillBytesForFlow(testerserverGetFlowId(t, l), sbufGetMutablePtr(buf) + header_len,
                                     payload_len - header_len, chunk_index, chunk_offset, direction);
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

        if (! testerserverDecodePacketIpv4(t, buf, direction, &packet_payload, &payload_len))
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
            sbuf_t *buf = bufferqueuePopFront(&ls->response_queue);

            ls->response_tx_index += 1;
            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
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

    const uint8_t chunk_count = testerserverGetChunkCount(t);
    uint8_t       response_limit = ts->streaming_response ? ls->request_rx_index : (ls->response_ready ? chunk_count : 0);

    while (! ls->response_paused && ls->response_tx_index < response_limit)
    {
        uint32_t chunk_size = testerserverGetChunkSize(t, ls->response_tx_index);
        uint32_t remaining  = chunk_size - ls->response_tx_offset;
        uint32_t max_len    = bufferpoolGetLargeBufferSize(pool);

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
    }

    if (ls->response_tx_index == chunk_count)
    {
        ls->response_sent = true;
    }
}
