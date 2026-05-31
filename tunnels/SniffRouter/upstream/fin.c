#include "structure.h"

void sniffrouterTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return;
    }

    uint8_t   route  = ls->decided;
    tunnel_t *target = ls->target;

    ls->prev_finished = true;
    ls->next_finished = true;

    lineLock(l);
    sniffrouterLinestateDestroy(l, ls);

    if (route == kSniffRouteTarget)
    {
        tunnelUpStreamFin(target, l);
    }
    else if (route == kSniffRouteDefault)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}
