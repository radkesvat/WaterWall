#include "structure.h"

void trojanserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kTrojanServerLineKindUdpRemote ||
        (ls->line_kind == kTrojanServerLineKindClient &&
         (ls->phase == kTrojanServerPhaseUdpWaitPacket || ls->phase == kTrojanServerPhaseUdpConnecting ||
          ls->phase == kTrojanServerPhaseUdpEstablished)))
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}
