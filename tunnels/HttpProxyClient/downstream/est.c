#include "internal.h"
void httpproxyclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    tunnelPrevDownStreamEst(t, l);
}
