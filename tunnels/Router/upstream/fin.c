#include "structure.h"

void routerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return;
    }

    uint8_t   route  = ls->decided;
    tunnel_t *target = ls->target;

    // Mark both directions finished before destroying state and propagating, so
    // any re-entrant callback observes a fully closed line and does not reflect.
    ls->prev_finished = true;
    ls->next_finished = true;

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
