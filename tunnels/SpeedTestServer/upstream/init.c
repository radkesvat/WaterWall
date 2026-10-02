#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    speedtestserverLinestateInitialize(ls, t, l);
    if (ls->recv_stream == NULL)
    {
        speedtestserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}

