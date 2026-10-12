#include "structure.h"

void reverseserverTunnelDownStreamResume(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *ls = lineGetState(u, t);
    ls->output_paused          = false;
    if (! ls->paired)
        return;
    reverseserverDrainPair(t, ls->u);
}
