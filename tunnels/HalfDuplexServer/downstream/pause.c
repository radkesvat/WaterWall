#include "structure.h"

void halfduplexserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->upload_line);
    ls->next_paused = true;
    if ((! ls->startup_active && ! ls->startup_initializing && ! ls->startup_dispatching) || ! ls->source_paused)
    {
        ls->source_paused = true;
        tunnelPrevDownStreamPause(t, ls->upload_line);
    }
}
