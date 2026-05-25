#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role != kConnectionFisherClientRoleChild)
    {
        return;
    }

    if (! lineIsEstablished(l))
    {
        lineMarkEstablished(l);
    }

    if (ls->main_line == NULL || ! lineIsAlive(ls->main_line))
    {
        return;
    }

    connectionfisherclient_lstate_t *main_ls = lineGetState(ls->main_line, t);
    if (main_ls->role != kConnectionFisherClientRoleMain || main_ls->selected_child != l || main_ls->main_est_forwarded)
    {
        return;
    }

    main_ls->main_est_forwarded = true;
    if (! lineIsEstablished(ls->main_line))
    {
        lineMarkEstablished(ls->main_line);
    }

    discard withLineLocked(ls->main_line, tunnelPrevDownStreamEst, t);
}
