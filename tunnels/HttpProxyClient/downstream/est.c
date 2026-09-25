#include "structure.h"
void httpproxyclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished || ls->est_sent)
        return;
    ls->est_sent = true;
    tunnelPrevDownStreamEst(t, l);
}
