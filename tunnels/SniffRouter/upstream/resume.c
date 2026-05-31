#include "structure.h"

void sniffrouterTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    if (ls->decided == kSniffRouteWeb)
    {
        tunnelUpStreamResume(ts->web_tunnel, l);
    }
    else if (ls->decided == kSniffRouteTunnel)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
