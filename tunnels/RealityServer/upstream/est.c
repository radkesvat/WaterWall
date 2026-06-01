#include "structure.h"

void realityserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->mode == kRealityServerModeAuthorized)
    {
        tunnelNextUpStreamEst(t, l);
        return;
    }

    if (! ls->destination_up_finished)
    {
        tunnelUpStreamEst(ts->destination_tunnel, l);
    }
}
