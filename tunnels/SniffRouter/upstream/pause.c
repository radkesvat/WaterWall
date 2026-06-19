#include "structure.h"

void sniffrouterTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kSniffRouteTarget)
    {
        tunnelUpStreamPause(ls->target, l);
    }
    else if (ls->decided == kSniffRouteDefault)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
