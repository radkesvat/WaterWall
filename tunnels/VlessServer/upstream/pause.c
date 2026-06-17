#include "structure.h"

void vlessserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        return;
    }

    if (ls->phase == kVlessServerPhaseTcpConnecting || ls->phase == kVlessServerPhaseTcpEstablished)
    {
        tunnelNextUpStreamPause(t, l);
        return;
    }

    if (ls->phase == kVlessServerPhaseUdpConnecting || ls->phase == kVlessServerPhaseUdpEstablished)
    {
        line_t *remote_l = ls->udp_remote_line;
        if (LIKELY(remote_l != NULL && lineIsAlive(remote_l)))
        {
            discard withLineLocked(remote_l, tunnelNextUpStreamPause, t);
        }
    }
}
