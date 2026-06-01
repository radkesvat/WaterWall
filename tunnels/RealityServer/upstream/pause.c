#include "structure.h"

void realityserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->mode == kRealityServerModeAuthorized)
    {
        tunnelNextUpStreamPause(t, l);
        return;
    }

    if (! ls->destination_up_finished)
    {
        tunnelUpStreamPause(ts->destination_tunnel, l);
    }
}
