#include "structure.h"

void routerTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    if (ls->decided == kRouterRouteTarget)
    {
        tunnelUpStreamResume(ls->target, l);
    }
    else if (ls->decided == kRouterRouteDefault)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
