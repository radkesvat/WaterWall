#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *tryReadCompletePacket(buffer_stream_t *stream)
{
    if (bufferstreamGetBufLen(stream) < kHeaderSize + 1)
    {
        return NULL;
    }

    uint8_t packet_first_bytes[kHeaderSize];
    bufferstreamViewBytesAt(stream, 0, packet_first_bytes, kHeaderSize);

    uint16_t total_packet_size_network;
    sbufByteCopy(&total_packet_size_network, packet_first_bytes, (uint32_t) sizeof(total_packet_size_network));
    uint16_t total_packet_size = ntohs(total_packet_size_network);
    
    // Validate packet size (minimum IP header size, maximum reasonable size)
    if (total_packet_size < 1 || ((uint32_t) (total_packet_size  + kHeaderSize)) > (uint32_t) bufferstreamGetBufLen(stream))
    {
        return NULL;
    }

    // Read the complete packet (header + payload)
    sbuf_t *packet_buffer = bufferstreamReadExact(stream, kHeaderSize + total_packet_size);
    sbufShiftRight(packet_buffer, kHeaderSize);

    return packet_buffer;
}

static void setDestinationProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
}

static bool initializeUpstream(tunnel_t *t, line_t *l, udpovertcpserver_lstate_t *ls, uint8_t protocol)
{
    setDestinationProtocol(l, protocol);
    ls->upstream_initialized = true;
    return withLineLocked(l, tunnelNextUpStreamInit, t);
}

static bool consumeProtocolMarker(tunnel_t *t, line_t *l, udpovertcpserver_lstate_t *ls)
{
    if (bufferstreamGetBufLen(&ls->read_stream) < kProtocolMarkerSize)
    {
        return true;
    }

    uint8_t protocol = bufferstreamViewByteAt(&ls->read_stream, kHeaderSize);
    sbuf_t *marker = bufferstreamReadExact(&ls->read_stream, kProtocolMarkerSize);
    lineReuseBuffer(l, marker);

    if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP)
    {
        LOGW("UdpOverTcpServer: invalid protocol marker: %u", (unsigned int) protocol);
        bufferstreamEmpty(&ls->read_stream);
        return false;
    }

    return initializeUpstream(t, l, ls, protocol);
}

static bool ensureUpstreamInitialized(tunnel_t *t, line_t *l, udpovertcpserver_lstate_t *ls)
{
    if (ls->upstream_initialized)
    {
        return true;
    }

    if (bufferstreamGetBufLen(&ls->read_stream) < kHeaderSize)
    {
        return true;
    }

    uint8_t packet_first_bytes[kHeaderSize];
    bufferstreamViewBytesAt(&ls->read_stream, 0, packet_first_bytes, kHeaderSize);

    uint16_t total_packet_size_network;
    sbufByteCopy(&total_packet_size_network, packet_first_bytes, (uint32_t) sizeof(total_packet_size_network));
    uint16_t total_packet_size = ntohs(total_packet_size_network);

    if (total_packet_size == 0)
    {
        return consumeProtocolMarker(t, l, ls);
    }

    return initializeUpstream(t, l, ls, IP_PROTO_UDP);
}

static bool isOverFlow(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > (uint32_t) (kMaxAllowedUDPPacketLength * 2))
    {
        LOGW("UdpOverTcpServer: UpStreamPayload: Read stream overflow, size: %zu, limit: %zu",
             bufferstreamGetBufLen(read_stream), (uint32_t) (kMaxAllowedUDPPacketLength * 2));
        return true; // Return true when overflow IS detected
    }
    return false; // Return false when no overflow
}

void udpovertcpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&(ls->read_stream), buf);

    if (! ensureUpstreamInitialized(t, l, ls))
    {
        return;
    }

    while (true)
    {
        if (! ensureUpstreamInitialized(t, l, ls))
        {
            return;
        }
        if (! ls->upstream_initialized)
        {
            break;
        }

        sbuf_t *packet_buffer = tryReadCompletePacket(&(ls->read_stream));

        if (! packet_buffer)
        {
            break; // No complete packet available, exit the loop
        }

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, packet_buffer))
        {
            return; // Exit if the line is no longer alive
        }
    }

    if (isOverFlow(&(ls->read_stream)))
    {
        bufferstreamEmpty(&(ls->read_stream));
    }
}
