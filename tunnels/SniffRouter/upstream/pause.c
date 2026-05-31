#include "structure.h"

void sniffrouterTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    if (ls->decided == kSniffRouteTarget)
    {
        tunnelUpStreamPause(ls->target, l);
    }
    else if (ls->decided == kSniffRouteDefault)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
