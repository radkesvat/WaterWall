#include "internal.h"

void trojanserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        return;
    }

    if (trojanserverIsUdp(ls))
    {
        return;
    }

    trojanserverOnNextEstablished(t, l, ls);
}
