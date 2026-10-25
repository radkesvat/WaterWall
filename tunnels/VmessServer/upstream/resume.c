#include "internal.h"

void vmessserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
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

    ls->response_paused = false;

    if (UNLIKELY(ls->phase == kVmessServerPhaseFallback))
    {
        tunnel_t *fallback = ((vmessserver_tstate_t *) tunnelGetState(t))->fallback_tunnel;
        if (LIKELY(fallback != NULL))
        {
            tunnelUpStreamResume(fallback, l);
        }
        return;
    }

    if (ls->phase == kVmessServerPhaseTcpConnecting || ls->phase == kVmessServerPhaseTcpEstablished)
    {
        tunnelNextUpStreamResume(t, l);
        return;
    }

    if (bufferqueueGetBufCount(&ls->pending_down) != 0 && ! vmessserverDrainResponse(t, l, false))
    {
        return;
    }
    ls = lineGetState(l, t);
    if (ls->response_paused)
        return;

    if (ls->phase == kVmessServerPhaseUdpConnecting || ls->phase == kVmessServerPhaseUdpEstablished)
    {
        vmessserverNotifyUdpPermission(t, l);
    }
}
