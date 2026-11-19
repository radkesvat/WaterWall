#include "structure.h"

void halfduplexserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    ls->next_paused               = true;
    if (closeDrainIsActive(&ls->close_drain))
        return;
    assert(ls->upload_line);
    if ((! ls->startup_active && ! ls->startup_initializing && ! ls->startup_dispatching) || ! ls->source_paused)
    {
        ls->source_paused = true;
        tunnelPrevDownStreamPause(ls->upload_tunnel, ls->upload_line);
    }
}
