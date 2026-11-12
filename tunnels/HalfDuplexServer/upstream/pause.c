#include "structure.h"

void halfduplexserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    // A transport can report pressure before the intro identifies its role.
    ls->transport_paused = true;
    if (ls->download_line == l && ls->main_line != NULL)
    {
        tunnel_t                  *owner   = halfduplexserverOwner(t);
        halfduplexserver_lstate_t *main_ls = lineGetState(ls->main_line, owner);
        if (! main_ls->startup_initializing)
            tunnelNextUpStreamPause(owner, ls->main_line);
    }
}
