#include "structure.h"

void routerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kRouterRouteTarget)
    {
        tunnelUpStreamPause(ls->target, l);
    }
    else if (ls->decided == kRouterRouteDefault)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
