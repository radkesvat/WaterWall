#include "structure.h"

void sniffrouterTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided == kSniffRouteTarget)
    {
        tunnelUpStreamResume(ls->target, l);
    }
    else if (ls->decided == kSniffRouteDefault)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
