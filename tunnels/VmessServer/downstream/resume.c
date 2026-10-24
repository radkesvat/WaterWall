#include "internal.h"

void vmessserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVmessServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kVmessServerLineKindUdpRemote)
    {
        vmessserverSetUdpBackendPaused(t, l, false);
        return;
    }

    if (ls->phase == kVmessServerPhaseUdpConnecting || ls->phase == kVmessServerPhaseUdpEstablished)
    {
        return;
    }

    tunnelPrevDownStreamResume(t, l);
}
