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

    if (total_packet_size < 1 || ((uint32_t) (total_packet_size  + kHeaderSize)) > (uint32_t) bufferstreamGetBufLen(stream))
    {
        return NULL;
    }

    // Read the complete packet (header + payload)
    sbuf_t *packet_buffer = bufferstreamReadExact(stream, kHeaderSize + total_packet_size);
    sbufShiftRight(packet_buffer, kHeaderSize);

    return packet_buffer;
}

static bool isOverFlow(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > (uint32_t) (kMaxAllowedUDPPacketLength * 2))
    {
        LOGW("UdpOverTcpClient: DownStreamPayload: Read stream overflow, size: %zu, limit: %zu",
             bufferstreamGetBufLen(read_stream), (uint32_t) (kMaxAllowedUDPPacketLength * 2));
        return true; // Return true when overflow IS detected
    }
    return false; // Return false when no overflow
}

void udpovertcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&(ls->read_stream), buf);

    while (true)
    {
        sbuf_t *packet_buffer = tryReadCompletePacket(&(ls->read_stream));

        if (! packet_buffer)
        {
            break; // No complete packet available, exit the loop
        }

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, packet_buffer))
        {
            return; // Exit if the line is no longer alive
        }
    }

    if (isOverFlow(&(ls->read_stream)))
    {
        bufferstreamEmpty(&(ls->read_stream));
    }
}
