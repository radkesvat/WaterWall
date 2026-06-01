#include "structure.h"

void realityclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! ls->tls_ready)
    {
        lineReuseBuffer(l, buf);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    realityclientProcessDownstream(t, l, buf);
}
