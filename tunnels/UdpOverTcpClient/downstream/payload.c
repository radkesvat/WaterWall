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
        const size_t bytes  = splicestreamLength(ls->read_stream);
        const size_t charge = splicestreamCharge(ls->read_stream);
        if (bytes > kMaxReentryBytes || sbufGetLength(buf) > kMaxReentryBytes - bytes || charge > kReadChargeLimit ||
            sbufGetQueueCharge(buf) > kReadChargeLimit - charge)
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
        sbuf_t *destination = tunnelGetChain(t)->supports_splice ? bufferpoolGetSpliceBuffer(ls->pool) : NULL;
        sbuf_t *body        = splicestreamMoveFrame(ls->read_stream, destination, length);
        if (! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, body) || ls->read_stream == NULL)
        {
            lineUnref(l);
            return;
        }
    }
    /* Drain complete coalesced frames before bounding the incomplete suffix. */
    if (splicestreamCharge(ls->read_stream) > kReadChargeLimit)
        discard splicestreamCompact(ls->read_stream);
    if (splicestreamLength(ls->read_stream) > kReadOverflowLimit ||
        splicestreamCharge(ls->read_stream) > kReadChargeLimit)
    {
        LOGW("UdpOverTcpClient: incomplete frame storage limit exceeded");
        udpovertcpclientCloseLine(t, l);
        lineUnref(l);
        return;
    }
    ls->read_draining = false;
    lineUnref(l);
}
