#include "structure.h"

void realityserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    bool handoff_cutoff        = ls->mode == kRealityServerModeHandoffAwaitConfirm && ls->destination_downstream_cutoff;
    if (! ls->closing_destination_for_authorized && ! handoff_cutoff && ! ls->terminal_closing && ! ls->prev_finished)
    {
        tunnelPrevDownStreamPause(t, l);
    }
}
