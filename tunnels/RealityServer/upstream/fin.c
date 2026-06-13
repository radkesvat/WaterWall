#include "structure.h"

void realityserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    bool close_protected = ls->mode == kRealityServerModeAuthorized && ls->protected_init_sent;
    bool close_destination =
        ls->mode != kRealityServerModeAuthorized && ls->destination_init_sent && ! ls->destination_up_finished;

    realityserverLinestateDestroy(ls);

    if (close_protected)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    else if (close_destination)
    {
        tunnelUpStreamFin(ts->destination_tunnel, l);
    }
}
