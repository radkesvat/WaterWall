#include "structure.h"

void routerTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->route == kRouterRouteTarget)
    {
        tunnelUpStreamResume(ls->target, l);
    }
    else if (ls->route == kRouterRouteDefault)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
