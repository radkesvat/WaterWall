#include "structure.h"

void reverseserverTunnelUpStreamPause(tunnel_t *t, line_t *d)
{
    reverseserver_lstate_t *ls = lineGetState(d, t);
    ls->output_paused          = true;
    if (! ls->paired)
        return;
    reverseserverReconcileSource(t, ls->u);
}
