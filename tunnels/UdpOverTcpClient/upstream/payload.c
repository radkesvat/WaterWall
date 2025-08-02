#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    uint32_t packet_length = sbufGetLength(buf);

#ifdef DEBUG
    if(sbufGetLength(buf) <= 0)
    {
        LOGF("UdpOverTcpClient: Received empty payload, this is a bug, our eventloop logic dose not allow read of size 0");
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        terminateProgram(1);
        return;
    }
#endif

    if(packet_length > kMaxAllowedPacketLength)
    {
        LOGW("UdpOverTcpClient: Packet length exceeds maximum allowed size: %u > %u , dropped", packet_length, kMaxAllowedPacketLength);
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        return;
    }
    // safely cast to uint16_t, since kMaxAllowedPacketLength is lower than 65536
    uint16_t packet_length_network = htons(packet_length);

    sbufShiftLeft(buf, sizeof(uint16_t));
    // cant gurantee the alignment of the buffer, so we use unaligned write
    sbufWriteUnAlignedUI16(buf, packet_length_network);

    tunnelNextUpStreamPayload(t, l, buf);
}
