#include "structure.h"

void routerTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    tunnelPrevDownStreamPause(t, l);
}
