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
            discard withLineLocked(client_l, tunnelPrevDownStreamResume, t);
        }
        return;
    }

    tunnelPrevDownStreamResume(t, l);
}
