#include "structure.h"

void routerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->route == kRouterRouteTarget)
    {
        tunnelUpStreamPause(ls->target, l);
    }
    else if (ls->route == kRouterRouteDefault)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
