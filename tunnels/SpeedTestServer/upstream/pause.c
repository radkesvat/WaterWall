#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    discard t;
    ls->send_paused = true;
}

