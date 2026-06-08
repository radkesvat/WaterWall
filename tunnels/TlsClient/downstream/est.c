#include "structure.h"
#include "race.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (tlsclientRaceIsMainLine(ls))
    {
        return;
    }

    if (tlsclientRaceIsChildLine(ls))
    {
        if (! lineIsEstablished(l))
        {
            lineMarkEstablished(l);
        }

        line_t *main_l = ls->race_main_line;
        if (main_l != NULL && lineIsAlive(main_l))
        {
            tlsclient_lstate_t *main_ls = lineGetState(main_l, t);
            if (main_ls->role == kTlsClientLineRoleRaceMain && main_ls->race_selected_child == l &&
                ls->handshake_completed && ! main_ls->race_main_est_forwarded)
            {
                main_ls->race_main_est_forwarded = true;
                if (! lineIsEstablished(main_l))
                {
                    lineMarkEstablished(main_l);
                }
                discard withLineLocked(main_l, tunnelPrevDownStreamEst, t);
            }
        }
        return;
    }

    if (ts->handshake_takeover_enabled)
    {
        discard l;
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}
