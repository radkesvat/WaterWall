#include "structure.h"

void routerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}
