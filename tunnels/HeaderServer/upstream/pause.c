#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kHeaderServerPhaseEstablished)
    {
        tunnelNextUpStreamPause(t, l);
    }
}
