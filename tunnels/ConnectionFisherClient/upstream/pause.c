#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleMain)
        ls->prev_paused = true;

    if (ls->role == kConnectionFisherClientRoleMain && ls->selected_child != NULL)
    {
        connectionfisherclientSetReplyPaused(t, ls->selected_child, true);
        return;
    }

    if (ls->role == kConnectionFisherClientRoleChild)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
