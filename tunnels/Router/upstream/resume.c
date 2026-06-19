#include "structure.h"

void routerTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kRouterRouteTarget)
    {
        tunnelUpStreamResume(ls->target, l);
    }
    else if (ls->decided == kRouterRouteDefault)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
