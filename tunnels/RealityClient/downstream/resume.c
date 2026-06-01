#include "structure.h"

void realityclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->prev_finished)
    {
        tunnelPrevDownStreamResume(t, l);
    }
}
