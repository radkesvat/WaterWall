#include "structure.h"

void sniffrouterTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    /*
     * Route targets are often adapter/server nodes whose upstream Est is not a
     * valid callback. Preserve the old SniffRouter behavior and only forward
     * upstream Est to the normal fallback branch.
     */
    if (ls->decided == kSniffRouteDefault)
    {
        tunnelNextUpStreamEst(t, l);
    }
}
