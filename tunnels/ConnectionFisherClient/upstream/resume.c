#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleMain && ls->selected_child != NULL)
    {
        discard withLineLocked(ls->selected_child, tunnelNextUpStreamResume, t);
        return;
    }

    if (ls->role == kConnectionFisherClientRoleChild)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
