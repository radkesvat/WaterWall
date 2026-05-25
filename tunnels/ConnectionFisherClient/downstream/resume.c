#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role != kConnectionFisherClientRoleChild)
    {
        return;
    }

    if (ls->child_handshake_complete && ls->main_line != NULL && lineIsAlive(ls->main_line))
    {
        connectionfisherclient_lstate_t *main_ls = lineGetState(ls->main_line, t);
        if (main_ls->role == kConnectionFisherClientRoleMain && main_ls->selected_child == l)
        {
            discard withLineLocked(ls->main_line, tunnelPrevDownStreamResume, t);
        }
    }
}
