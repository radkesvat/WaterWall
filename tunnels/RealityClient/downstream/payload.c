#include "structure.h"

void realityclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_lstate_t *ls = lineGetState(l, t);

    if (! ls->session_keys_ready)
    {
        lineReuseBuffer(l, buf);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    realityclientProcessDownstream(t, l, buf);
}
