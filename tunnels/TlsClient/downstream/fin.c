#include "structure.h"
#include "race.h"
#include "sni_pool.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (tlsclientRaceIsMainLine(ls))
    {
        tlsclientRaceCloseMainLine(t, l);
        return;
    }

    if (tlsclientRaceIsChildLine(ls))
    {
        bool force_close_main = false;
        line_t *main_l = ls->race_main_line;

        tlsclientRecordSniFailureForLine(t, ls);

        if (main_l != NULL && lineIsAlive(main_l))
        {
            tlsclient_lstate_t *main_ls = lineGetState(main_l, t);
            force_close_main = main_ls->role == kTlsClientLineRoleRaceMain && main_ls->race_selected_child == l;
        }

        tlsclientRaceCloseChildLineFromDownstream(t, l, force_close_main);
        return;
    }

    tlsclientRecordSniFailureForLine(t, ls);
    tlsclientReleaseActiveSniLine(t, ls);
    tlsclientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
