#include "structure.h"

void vlessserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kVlessServerLineKindUdpRemote ||
        (ls->line_kind == kVlessServerLineKindClient &&
         (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
          ls->phase == kVlessServerPhaseUdpEstablished)))
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}
