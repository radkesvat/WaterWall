#include "structure.h"

void trojanserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        trojanserverOnSelectedEstablished(t, l, ls);
        return;
    }

    if (ls->line_kind == kTrojanServerLineKindClient &&
        (ls->phase == kTrojanServerPhaseUdpWaitPacket || ls->phase == kTrojanServerPhaseUdpConnecting ||
         ls->phase == kTrojanServerPhaseUdpEstablished))
    {
        return;
    }

    trojanserverOnSelectedEstablished(t, l, ls);
}
