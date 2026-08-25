#include "structure.h"

void trojanserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        line_t *client_l = ls->client_line;
        if (LIKELY(client_l != NULL && lineIsAlive(client_l)))
        {
            discard lineCallWithRef(client_l, tunnelPrevDownStreamResume, t);
        }
        return;
    }

    if (ls->branch == kTrojanServerBranchFallback)
    {
        ls->fallback_payload_paused = false;
        if (UNLIKELY(! trojanserverScheduleFallbackPayloadDrain(t, l, ls)))
        {
            trojanserverCloseLineBidirectional(t, l);
            return;
        }
        if (! lineIsAlive(l))
        {
            return;
        }
    }

    tunnelPrevDownStreamResume(t, l);
}
