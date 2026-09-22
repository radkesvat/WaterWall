#include "structure.h"

void trojanserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->fallback_close_draining)
        return;
    trojanserverLinestateInitialize(ls, t, l, kTrojanServerLineKindClient);
}
