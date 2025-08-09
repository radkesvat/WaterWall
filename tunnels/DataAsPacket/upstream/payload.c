#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *tryReadCompletePacket(buffer_stream_t *stream)
{
    if (bufferstreamGetBufLen(stream) < IP_HLEN)
    {
        return NULL;
    }

    uint8_t ip_header_bytes[IP_HLEN];
    bufferstreamViewBytesAt(stream, 0, ip_header_bytes, IP_HLEN);

    struct ip_hdr *ip_header = (struct ip_hdr *) ip_header_bytes;

    if (IPH_V(ip_header) != 4)
    {
        LOGW("DataAsPacket: UpStreamPayload: Not an IPv4 packet, skipping one byte");

        assert(false); // debug this if happens
        // Skip one byte to avoid infinite loop on corrupted data
        sbuf_t *skip_buf = bufferstreamReadExact(stream, 1);
        if (skip_buf)
        {
            bufferpoolReuseBuffer(stream->pool, skip_buf);
        }
        return NULL; // Not an IPv4 packet
    }

    size_t total_packet_size = lwip_ntohs(IPH_LEN(ip_header));

    // Validate packet size (minimum IP header size, maximum reasonable size)
    if (total_packet_size < IP_HLEN || total_packet_size > 65535 || total_packet_size > bufferstreamGetBufLen(stream))
    {
        return NULL;
    }

    // Read the complete packet (header + payload)
    return bufferstreamReadExact(stream, total_packet_size);
}

static bool isOverFlow(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > kMaxBufferSize)
    {
        LOGW("DataAsPacket: UpStreamPayload: Read stream overflow, size: %zu, limit: %zu", bufferstreamGetBufLen(read_stream),
             kMaxBufferSize);
        return true; // Return true when overflow IS detected
    }
    return false; // Return false when no overflow
}

void dataaspacketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    dataaspacket_lstate_t *ls = lineGetState(tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), t);

    bufferstreamPush(&(ls->read_stream), buf);

    if (isOverFlow(&(ls->read_stream)))
    {
        bufferstreamEmpty(&(ls->read_stream));
        return;
    }

    lineLock(l);
    while (true)
    {
        sbuf_t *packet_buffer = tryReadCompletePacket(&(ls->read_stream));

        if (! packet_buffer)
        {
            break; // No complete packet available, exit the loop
        }

        tunnelNextUpStreamPayload(t, tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), packet_buffer);
        if (! lineIsAlive(l))
        {
            break; // Exit if the line is no longer alive
        }
    }
    lineUnlock(l);
}
