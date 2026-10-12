#include "internal.h"
void httpproxyclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    tunnelPrevDownStreamResume(t, l);
}
