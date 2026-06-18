#include "structure.h"

void routerTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    /*
     * Rule targets are often adapter/server nodes whose upstream Est is not a
     * valid callback. Only forward upstream Est to the normal default branch.
     */
    if (ls->decided == kRouterRouteDefault)
    {
        tunnelNextUpStreamEst(t, l);
    }
}
