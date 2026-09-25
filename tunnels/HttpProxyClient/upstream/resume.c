#include "structure.h"
void httpproxyclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    ls->prev_paused = false;
    if (ls->next_init && ! lineCallWithRef(l, tunnelNextUpStreamResume, t))
        return;
    hpcDrainResponse(t, l);
}
