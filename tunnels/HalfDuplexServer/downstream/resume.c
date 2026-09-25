#include "structure.h"

void halfduplexserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->upload_line);
    ls->next_paused = false;
    if (! ls->startup_active && ! ls->startup_initializing && ! ls->startup_dispatching)
    {
        ls->source_paused = false;
        tunnelPrevDownStreamResume(t, ls->upload_line);
        return;
    }
    halfduplexserverReplayStartup(t, l);
}
