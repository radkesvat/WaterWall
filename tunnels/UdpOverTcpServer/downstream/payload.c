#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(buf != NULL);
    assert(spliceframereaderIsAttached(&((udpovertcpserver_lstate_t *) lineGetState(l, t))->reader));
    const uint32_t length = sbufGetLength(buf);
    if (length > kMaxAllowedUDPPacketLength)
    {
        udpovertcpserverLogSizeDrop(lineGetState(l, t), length);
        lineReuseBuffer(l, buf);
        return;
    }

    assert(sbufGetHeadroom(buf) >= kHeaderSize);
    sbufShiftLeft(buf, kHeaderSize);
    sbufWriteUnAlignedUI16(buf, htons((uint16_t) length));
    tunnelPrevDownStreamPayload(t, l, buf);
}
