#include "structure.h"

void halfduplexserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    ls->next_paused               = false;
    if (closeDrainIsActive(&ls->close_drain))
    {
        halfduplexserverPumpClose(t, l);
        return;
    }
    assert(ls->upload_line);
    if (! ls->startup_active && ! ls->startup_initializing && ! ls->startup_dispatching)
    {
        ls->source_paused = false;
        tunnelPrevDownStreamResume(ls->upload_tunnel, ls->upload_line);
        return;
    }
    halfduplexserverReplayStartup(t, l);
}
