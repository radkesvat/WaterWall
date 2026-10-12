#include "structure.h"

void tlsserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);
    if (ls->fallback_close_draining)
    {
        return;
    }
    tunnelPrevDownStreamPause(t, l);
}
