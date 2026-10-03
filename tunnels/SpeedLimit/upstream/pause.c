#include "structure.h"

#include "loggers/network_logger.h"

void speedlimitTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    speedlimit_lstate_t *ls         = lineGetState(l, t);
    bool                 was_paused = ls->next_side_externally_paused || ls->next_side_locally_paused;
    ls->next_side_externally_paused = true;
    if (! was_paused)
        tunnelNextUpStreamPause(t, l);
}
