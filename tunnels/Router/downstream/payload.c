#include "structure.h"

void routerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
