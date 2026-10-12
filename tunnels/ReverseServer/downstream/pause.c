#include "structure.h"

void reverseserverTunnelDownStreamPause(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *ls = lineGetState(u, t);
    ls->output_paused          = true;
    if (! ls->paired)
        return;
    reverseserverReconcileSource(t, ls->d);
}
