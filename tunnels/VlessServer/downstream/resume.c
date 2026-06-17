#include "structure.h"

void vlessserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        line_t *client_l = ls->client_line;
        if (LIKELY(client_l != NULL && lineIsAlive(client_l)))
        {
            discard withLineLocked(client_l, tunnelPrevDownStreamResume, t);
        }
        return;
    }

    if (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
        ls->phase == kVlessServerPhaseUdpEstablished)
    {
        return;
    }

    tunnelPrevDownStreamResume(t, l);
}
