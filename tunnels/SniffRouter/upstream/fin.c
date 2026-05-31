#include "structure.h"

void sniffrouterTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return;
    }

    uint8_t route = ls->decided;

    /*
     * Receiving upstream Finish means the previous side is no longer callable.
     * Mark both sides before forwarding so re-entrant downstream callbacks from
     * the chosen branch cannot reflect back into the already-closing previous
     * side.
     */
    ls->prev_finished = true;
    ls->next_finished = true;

    lineLock(l);

    if (route == kSniffRouteWeb)
    {
        tunnelUpStreamFin(ts->web_tunnel, l);
    }
    else if (route == kSniffRouteTunnel)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    sniffrouterLinestateDestroy(l, ls);
    lineUnlock(l);
}
