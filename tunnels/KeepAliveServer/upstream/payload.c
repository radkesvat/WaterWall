#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->read_stream != NULL);
    if (ls->read_draining &&
        (splicestreamLength(ls->read_stream) > kKeepAliveServerMaxReentryBytes ||
         sbufGetLength(buf) > kKeepAliveServerMaxReentryBytes - splicestreamLength(ls->read_stream)))
    {
        lineReuseBuffer(l, buf);
        keepaliveserverCloseLineFromProtocolError(t, l);
        return;
    }
    if (! splicestreamPush(ls->read_stream, buf))
    {
        keepaliveserverCloseLineFromProtocolError(t, l);
        return;
    }
    if (ls->read_draining)
    {
        if (splicestreamCharge(ls->read_stream) > kKeepAliveServerReadChargeLimit)
            discard splicestreamCompact(ls->read_stream);
        if (splicestreamCharge(ls->read_stream) > kKeepAliveServerReadChargeLimit)
            keepaliveserverCloseLineFromProtocolError(t, l);
        return;
    }

    if (! keepaliveserverConsumeUpstreamFrames(t, l))
    {
        return;
    }
}
