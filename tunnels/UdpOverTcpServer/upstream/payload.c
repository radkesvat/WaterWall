#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    switch (spliceframereaderAdmit(&ls->reader, buf))
    {
    case kSpliceFrameDrain:
        break;
    case kSpliceFrameQueued:
    case kSpliceFrameEmpty:
        return;
    case kSpliceFrameByteLimit:
        LOGW("UdpOverTcpServer: decoder reentry byte limit exceeded");
        udpovertcpserverCloseLine(t, l);
        return;
    case kSpliceFrameChargeLimit:
        LOGW("UdpOverTcpServer: decoder reentry storage limit exceeded");
        udpovertcpserverCloseLine(t, l);
        return;
    case kSpliceFramePushFailed:
        udpovertcpserverCloseLine(t, l);
        return;
    }
    lineRef(l);
    for (;;)
    {
        const uint8_t *header = spliceframereaderPeekHeader(&ls->reader);
        if (header == NULL)
            break;
        uint16_t network_length;
        sbufByteCopy(&network_length, header, kHeaderSize);
        const uint32_t length = ntohs(network_length);
        if (length == 0)
        {
            LOGW("UdpOverTcpServer: invalid zero-length data frame");
            udpovertcpserverCloseLine(t, l);
            lineUnref(l);
            return;
        }
        if (! spliceframereaderBodyReady(&ls->reader, length))
            break;
        sbuf_t *body = spliceframereaderTakeFrame(&ls->reader, length);
        tunnelNextUpStreamPayload(t, l, body);
        if (! lineIsAlive(l) || ! spliceframereaderIsAttached(&ls->reader))
        {
            lineUnref(l);
            return;
        }
    }
    /* Draining leaves at most 65,536 bytes in an incomplete frame, including its two-byte header. */
    assert(spliceframereaderLength(&ls->reader) < kHeaderSize + UINT16_MAX);
    if (! spliceframereaderEndDrain(&ls->reader))
    {
        LOGW("UdpOverTcpServer: incomplete frame storage limit exceeded");
        udpovertcpserverCloseLine(t, l);
        lineUnref(l);
        return;
    }
    lineUnref(l);
}
