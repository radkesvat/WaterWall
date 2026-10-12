#include "internal.h"
void httpproxyclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    if (ls->next_init)
        tunnelNextUpStreamResume(t, l);
}
