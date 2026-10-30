#include "internal.h"

void trojanserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->tunnel == t && ls->phase == kTrojanServerPhaseClosing)
        return;
    trojanserverLinestateInitialize(ls, t, l, kTrojanServerLineKindClient);
}
