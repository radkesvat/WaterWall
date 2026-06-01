#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);

    bool ok;
    if (! ls->open_sent)
    {
        ls->open_sent = true;
        ok            = bgp4clientWrapFirstOpenPayload(t, l, &buf);
    }
    else
    {
        ok = bgp4clientWrapPayload(t, l, &buf, bgp4clientNextPayloadType());
    }

    if (! ok)
    {
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
