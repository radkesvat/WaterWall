#include "structure.h"

void tlsserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);
    if (ls->fallback_close_draining)
    {
        return;
    }
    tunnelPrevDownStreamResume(t, l);
}
