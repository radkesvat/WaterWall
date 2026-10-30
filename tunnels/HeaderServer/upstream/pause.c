#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kHeaderServerPhaseWaitHeader)
    {
        ls->pending_next_pause = true;
        return;
    }
    if (ls->phase == kHeaderServerPhaseEstablished)
    {
        ls->pending_next_pause = false;
        tunnelNextUpStreamPause(t, l);
    }
}
