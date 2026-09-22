#include "structure.h"

void trojanserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanServerPhaseClosing)
        return;
    assert(ls->line_kind != kTrojanServerLineKindUdpRemote);
    ls->prev_paused = true;
    trojanserverPump(t, l);
}
