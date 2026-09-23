#include "structure.h"

void vlessserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        vlessserverOnSelectedEstablished(t, l, ls);
        return;
    }

    if (ls->line_kind == kVlessServerLineKindClient &&
        (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
         ls->phase == kVlessServerPhaseUdpEstablished))
    {
        return;
    }

    if (ls->phase == kVlessServerPhaseFallback)
    {
        if (! ls->transport_est_sent)
        {
            ls->transport_est_sent = true;
            tunnelPrevDownStreamEst(t, l);
        }
        return;
    }

    vlessserverOnSelectedEstablished(t, l, ls);
}
