#include "internal.h"

void trojanserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanServerPhaseClosing)
        return;
    assert(ls->line_kind != kTrojanServerLineKindUdpRemote);
    ls->prev_paused = false;
    if (trojanserverIsUdp(ls))
    {
        trojanserverPump(t, l);
        return;
    }
    /* Retain the latest state until branch selection supplies an initialized target. */
    if (! ls->next_initialized)
        return;
    ls->next_pause_sent = false;
    if (ls->branch == kTrojanServerBranchFallback)
        tunnelUpStreamResume(trojanserverSelectedUpstream(t, ls), l);
    else
        tunnelNextUpStreamResume(t, l);
}
