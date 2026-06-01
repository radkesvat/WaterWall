#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4server_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&ls->read_stream, buf);

    while (true)
    {
        sbuf_t *body = NULL;
        if (! bgp4serverReadFrame(t, l, &ls->read_stream, &body))
        {
            bgp4serverCloseLine(t, l);
            return;
        }

        if (body == NULL)
        {
            break;
        }

        if (! bgp4serverStripUpstreamBody(t, l, ls, body))
        {
            bgp4serverCloseLine(t, l);
            return;
        }

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, body))
        {
            return;
        }
    }
}
