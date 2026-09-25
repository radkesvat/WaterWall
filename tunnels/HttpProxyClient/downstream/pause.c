#include "structure.h"
void httpproxyclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    ls->next_paused = true;
    hpcPressure(t, l);
}
