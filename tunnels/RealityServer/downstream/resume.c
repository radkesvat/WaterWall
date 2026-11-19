#include "structure.h"

void realityserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    const bool              is_protected = ls->mode == kRealityServerModeAuthorized;
    if (ls->closing_destination_for_authorized || ls->terminal_closing || ls->prev_finished ||
        (is_protected ? ls->next_finished : ls->destination_downstream_cutoff || ls->destination_up_finished))
    {
        return;
    }
    if (is_protected)
        ls->protected_read_paused = false;
    if (ls->handoff_ack_dispatching)
        return;
    ls->frontend_read_paused = false;
    tunnelPrevDownStreamResume(t, l);
}
