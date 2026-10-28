#include "structure.h"

void sniffrouterTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kSniffRouteUndecided)
    {
        ls->pending_pause = true;
        return;
    }

    // Init reentry can already notify the selected branch; discard stale replay first.
    ls->pending_pause = false;
    if (ls->decided == kSniffRouteTarget)
    {
        tunnelUpStreamPause(ls->target, l);
    }
    else if (ls->decided == kSniffRouteDefault)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
