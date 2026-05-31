#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4server_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kBgp4ServerPhaseNone)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! bgp4serverWrapPayload(t, l, &buf, bgp4serverNextPayloadType()))
    {
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
