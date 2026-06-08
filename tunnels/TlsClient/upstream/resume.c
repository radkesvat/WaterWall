#include "structure.h"
#include "race.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (tlsclientRaceIsMainLine(ls))
    {
        if (ls->race_selected_child != NULL && lineIsAlive(ls->race_selected_child))
        {
            discard withLineLocked(ls->race_selected_child, tunnelNextUpStreamResume, t);
        }
        return;
    }

    tunnelNextUpStreamResume(t, l);
}
