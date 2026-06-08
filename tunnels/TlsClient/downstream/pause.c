#include "structure.h"
#include "race.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (tlsclientRaceIsMainLine(ls))
    {
        return;
    }

    if (tlsclientRaceIsChildLine(ls))
    {
        line_t *main_l = ls->race_main_line;
        if (main_l != NULL && lineIsAlive(main_l))
        {
            tlsclient_lstate_t *main_ls = lineGetState(main_l, t);
            if (main_ls->role == kTlsClientLineRoleRaceMain && main_ls->race_selected_child == l)
            {
                discard withLineLocked(main_l, tunnelPrevDownStreamPause, t);
            }
        }
        return;
    }

    tunnelPrevDownStreamPause(t, l);
}
