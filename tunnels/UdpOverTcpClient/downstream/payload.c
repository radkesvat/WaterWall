#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);
    switch (spliceframereaderAdmit(&ls->reader, buf))
    {
    case kSpliceFrameDrain:
        break;
    case kSpliceFrameQueued:
    case kSpliceFrameEmpty:
        return;
    case kSpliceFrameByteLimit:
        LOGW("UdpOverTcpClient: decoder reentry byte limit exceeded");
        udpovertcpclientCloseLine(t, l);
        return;
    case kSpliceFrameChargeLimit:
        LOGW("UdpOverTcpClient: decoder reentry storage limit exceeded");
        udpovertcpclientCloseLine(t, l);
        return;
    case kSpliceFramePushFailed:
        udpovertcpclientCloseLine(t, l);
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
            LOGW("UdpOverTcpClient: invalid zero-length data frame");
            udpovertcpclientCloseLine(t, l);
            lineUnref(l);
            return;
        }
        if (! spliceframereaderBodyReady(&ls->reader, length))
            break;
        sbuf_t *body = spliceframereaderTakeFrame(&ls->reader, length);
        tunnelPrevDownStreamPayload(t, l, body);
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
        LOGW("UdpOverTcpClient: incomplete frame storage limit exceeded");
        udpovertcpclientCloseLine(t, l);
        lineUnref(l);
        return;
    }
    lineUnref(l);
}
