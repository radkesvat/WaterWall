#include "structure.h"

#include "loggers/network_logger.h"

void speedlimitTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    speedlimit_lstate_t *ls         = lineGetState(l, t);
    bool                 was_paused = ls->next_side_externally_paused;
    ls->next_side_externally_paused = false;

    if (ls->next_side_locally_paused)
    {
        if (! speedlimitScheduleDownstreamDrain(ls, kSpeedLimitImmediateMs))
            speedlimitCloseLineOnDrainFailure(ls, NULL);
        return;
    }
    // Finish all local work before a callback that can close or reenter this line.
    if (was_paused)
        tunnelNextUpStreamResume(t, l);
}
