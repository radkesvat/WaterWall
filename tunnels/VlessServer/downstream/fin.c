#include "internal.h"

void vlessserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (fallbackReplayAbsorbBranchFinish(&ls->fallback))
        return;

    vlessserverCloseLineFromDownstream(t, l);
}
