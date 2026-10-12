#include "structure.h"

void reverseserverTunnelUpStreamResume(tunnel_t *t, line_t *d)
{
    reverseserver_lstate_t *ls = lineGetState(d, t);
    ls->output_paused          = false;
    if (! ls->paired)
        return;
    reverseserverDrainPair(t, ls->u);
}
