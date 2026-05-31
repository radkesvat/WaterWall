#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    ls->send_paused = false;
    speedtestserverScheduleSend(t, l, ls);
}

