#include "structure.h"

void realityserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    if (! ls->prev_finished && ! ls->closing_destination_for_authorized)
    {
        tunnelPrevDownStreamResume(t, l);
    }
}
