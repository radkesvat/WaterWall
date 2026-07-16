#include "structure.h"

void realityserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    if (ls->closing_destination_for_authorized || ls->prev_est_sent ||
        ls->terminal_closing || ls->prev_finished)
    {
        return;
    }

    ls->prev_est_sent = true;
    tunnelPrevDownStreamEst(t, l);
}
