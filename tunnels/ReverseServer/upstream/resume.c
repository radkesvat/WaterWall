#include "structure.h"

void reverseserverTunnelUpStreamResume(tunnel_t *t, line_t *d)
{
    reverseserver_lstate_t *ls = lineGetState(d, t);
    ls->output_paused          = false;
    if (! ls->paired)
        return;
    line_t *other = ls->u;
    lineRef(d);
    lineRef(other);
    reverseserverDrainPair(t, ls->u);
    lineUnref(other);
    lineUnref(d);
}
