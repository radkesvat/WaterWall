#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    ls->pending_next_pause = false;
    if (ls->phase == kHeaderServerPhaseEstablished)
    {
        tunnelNextUpStreamResume(t, l);
    }
}
