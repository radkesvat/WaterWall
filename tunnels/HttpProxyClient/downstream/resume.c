#include "structure.h"
void httpproxyclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    ls->next_paused = false;
    if (! hpcSendHeader(t, l) || ! hpcDrainUpload(t, l))
        return;
    hpcPressure(t, l);
}
