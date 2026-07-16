#include "structure.h"

void realityserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    if (! ls->closing_destination_for_authorized && ! ls->terminal_closing && ! ls->prev_finished)
    {
        tunnelPrevDownStreamResume(t, l);
    }
}
