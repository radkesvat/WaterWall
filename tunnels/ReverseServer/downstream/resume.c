#include "structure.h"

void reverseserverTunnelDownStreamResume(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *ls = lineGetState(u, t);
    ls->output_paused          = false;
    if (! ls->paired)
        return;
    line_t *other = ls->d;
    lineRef(u);
    lineRef(other);
    reverseserverDrainPair(t, ls->u);
    lineUnref(other);
    lineUnref(u);
}
