#include "structure.h"

void trojanserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    if (UNLIKELY(ls->branch == kTrojanServerBranchFallback))
    {
        tunnel_t *fallback = ((trojanserver_tstate_t *) tunnelGetState(t))->fallback_tunnel;
        if (LIKELY(fallback != NULL))
        {
            tunnelUpStreamPause(fallback, l);
        }
        return;
    }

    if (ls->branch == kTrojanServerBranchTrojan)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
