#include "structure.h"

void trojanserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
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
            tunnelUpStreamResume(fallback, l);
        }
        return;
    }

    if (ls->branch == kTrojanServerBranchTrojan)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
