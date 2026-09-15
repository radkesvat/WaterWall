#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);

    bool ok;
    if (! ls->open_sent)
    {
        ok = bgp4clientWrapFirstOpenPayload(t, l, &buf);
    }
    else
    {
        ok = bgp4clientWrapPayload(t, l, &buf, bgp4clientNextPayloadType());
    }

    if (! ok)
    {
        bgp4clientCloseLine(t, l);
        return;
    }
    ls->open_sent = true;

    tunnelNextUpStreamPayload(t, l, buf);
}
