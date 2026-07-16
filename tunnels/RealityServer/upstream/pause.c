#include "structure.h"

void realityserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->terminal_closing)
    {
        return;
    }

    if (ls->mode == kRealityServerModeAuthorized)
    {
        if (! ls->next_finished)
        {
            tunnelNextUpStreamPause(t, l);
        }
        return;
    }

    if (! ls->destination_up_finished)
    {
        tunnelUpStreamPause(ts->destination_tunnel, l);
    }
}
