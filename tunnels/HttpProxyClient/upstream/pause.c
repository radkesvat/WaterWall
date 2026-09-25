#include "structure.h"
void httpproxyclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    ls->prev_paused = true;
    if (ls->next_init)
        tunnelNextUpStreamPause(t, l);
}
