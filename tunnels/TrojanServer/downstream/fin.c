#include "internal.h"

void trojanserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (fallbackReplayAbsorbBranchFinish(&ls->fallback))
        return;

    trojanserverCloseLineFromDownstream(t, l);
}
