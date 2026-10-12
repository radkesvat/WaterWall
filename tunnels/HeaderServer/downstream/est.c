#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase != kHeaderServerPhaseEstablished)
    {
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}
