#include "structure.h"

void routerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->route == kRouterRouteUndecided)
    {
        ls->pending_pause = true;
        return;
    }

    // Init reentry can already notify the selected branch; discard stale replay first.
    ls->pending_pause = false;
    if (ls->route == kRouterRouteTarget)
    {
        tunnelUpStreamPause(ls->target, l);
    }
    else if (ls->route == kRouterRouteDefault)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
