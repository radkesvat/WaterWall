#include "internal.h"

void vmessserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVmessServerPhaseClosing || ls->next_finished))
    {
        return;
    }

    if (ls->line_kind == kVmessServerLineKindUdpRemote)
    {
        return;
    }

    ls->response_paused = true;

    if (UNLIKELY(ls->phase == kVmessServerPhaseFallback))
    {
        tunnel_t *fallback = ((vmessserver_tstate_t *) tunnelGetState(t))->fallback_tunnel;
        if (LIKELY(fallback != NULL))
        {
            tunnelUpStreamPause(fallback, l);
        }
        return;
    }

    if (ls->phase == kVmessServerPhaseTcpConnecting || ls->phase == kVmessServerPhaseTcpEstablished)
    {
        tunnelNextUpStreamPause(t, l);
        return;
    }

    if (ls->phase == kVmessServerPhaseUdpConnecting || ls->phase == kVmessServerPhaseUdpEstablished)
    {
        line_t *remote_l = ls->udp_remote_line;
        if (LIKELY(remote_l != NULL && lineIsAlive(remote_l)))
        {
            discard lineCallWithRef(remote_l, tunnelNextUpStreamPause, t);
        }
    }
}
