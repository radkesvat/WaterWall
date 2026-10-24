#include "internal.h"

void vmessserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVmessServerPhaseClosing || ls->next_finished))
    {
        return;
    }

    if (ls->line_kind == kVmessServerLineKindUdpRemote)
    {
        vmessserverOnSelectedEstablished(t, l, ls);
        return;
    }

    if (ls->line_kind == kVmessServerLineKindClient &&
        (ls->phase == kVmessServerPhaseUdpConnecting || ls->phase == kVmessServerPhaseUdpEstablished))
    {
        return;
    }

    if (ls->phase == kVmessServerPhaseFallback)
    {
        tunnelPrevDownStreamEst(t, l);
        return;
    }

    vmessserverOnSelectedEstablished(t, l, ls);
}
