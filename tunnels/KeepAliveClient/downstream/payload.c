#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    assert(ls->read_stream != NULL);
    if (ls->read_draining && (splicestreamLength(ls->read_stream) > kKeepAliveMaxReentryBytes ||
                              sbufGetLength(buf) > kKeepAliveMaxReentryBytes - splicestreamLength(ls->read_stream)))
    {
        lineReuseBuffer(l, buf);
        keepaliveclientCloseLineFromProtocolError(t, l);
        return;
    }
    if (! splicestreamPush(ls->read_stream, buf))
    {
        keepaliveclientCloseLineFromProtocolError(t, l);
        return;
    }
    if (ls->read_draining)
    {
        if (splicestreamCharge(ls->read_stream) > kKeepAliveReadChargeLimit)
            discard splicestreamCompact(ls->read_stream);
        if (splicestreamCharge(ls->read_stream) > kKeepAliveReadChargeLimit)
            keepaliveclientCloseLineFromProtocolError(t, l);
        return;
    }

    if (! keepaliveclientConsumeDownstreamFrames(t, l))
    {
        return;
    }
}
