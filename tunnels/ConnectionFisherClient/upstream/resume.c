#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleMain)
        ls->prev_paused = false;

    if (ls->role == kConnectionFisherClientRoleMain && ls->selected_child != NULL)
    {
        connectionfisherclientSetReplyPaused(t, ls->selected_child, false);
        return;
    }

    if (ls->role == kConnectionFisherClientRoleChild)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
