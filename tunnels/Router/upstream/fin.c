#include "structure.h"

void routerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    uint8_t   route  = ls->decided;
    tunnel_t *target = ls->target;

    lineLock(l);
    routerLinestateDestroy(l, ls);

    if (route == kRouterRouteTarget)
    {
        tunnelUpStreamFin(target, l);
    }
    else if (route == kRouterRouteDefault)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}
