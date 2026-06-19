#include "structure.h"

void sniffrouterTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    uint8_t   route  = ls->decided;
    tunnel_t *target = ls->target;

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
