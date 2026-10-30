#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->read_stream != NULL);
    if (sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->read_draining)
    {
        if (! splicestreamCanAdmit(ls->read_stream, buf, kMaxReentryBytes, kReadChargeLimit))
        {
            lineReuseBuffer(l, buf);
            LOGW("UdpOverTcpClient: decoder reentry limit exceeded");
            udpovertcpclientCloseLine(t, l);
            return;
        }
    }
    if (! splicestreamPush(ls->read_stream, buf))
    {
        udpovertcpclientCloseLine(t, l);
        return;
    }
    if (ls->read_draining)
        return;
    ls->read_draining = true;
    lineRef(l);
    for (;;)
    {
        const uint8_t *header = splicestreamPeekHeader(ls->read_stream);
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
        if (splicestreamBodyBytes(ls->read_stream) < length)
            break;
        sbuf_t *destination =
            tunnelGetChain(t)->supports_splice ? bufferpoolGetSpliceBuffer(lineGetBufferPool(l)) : NULL;
        sbuf_t *body        = splicestreamMoveFrame(ls->read_stream, destination, length);
        tunnelPrevDownStreamPayload(t, l, body);
        if (! lineIsAlive(l) || ls->read_stream == NULL)
        {
            lineUnref(l);
            return;
        }
    }
    /* Draining leaves at most 65,536 bytes in an incomplete frame, including its two-byte header. */
    assert(splicestreamLength(ls->read_stream) < kHeaderSize + UINT16_MAX);
    if (! splicestreamSettleCharge(ls->read_stream, kReadChargeLimit))
    {
        LOGW("UdpOverTcpClient: incomplete frame storage limit exceeded");
        udpovertcpclientCloseLine(t, l);
        lineUnref(l);
        return;
    }
    ls->read_draining = false;
    lineUnref(l);
}
