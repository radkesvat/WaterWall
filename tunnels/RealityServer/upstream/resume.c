#include "structure.h"

void realityserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->mode == kRealityServerModeAuthorized)
    {
        if (! ls->next_finished)
        {
            tunnelNextUpStreamResume(t, l);
        }
        return;
    }

    if (! ls->destination_up_finished)
    {
        tunnelUpStreamResume(ts->destination_tunnel, l);
    }
}
