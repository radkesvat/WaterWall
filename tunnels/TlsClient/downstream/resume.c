#include "structure.h"

void tlsclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (ls->upstream_finished)
    {
        return;
    }
    tunnelPrevDownStreamResume(t, l);
}
