#include "structure.h"

void vlessserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_close_draining)
    {
        // The previous side already finished before the final fallback Payload;
        // record this branch close instead of reflecting it or finishing twice.
        ls->fallback_branch_finished_during_drain = true;
        return;
    }

    vlessserverCloseLineFromDownstream(t, l);
}
