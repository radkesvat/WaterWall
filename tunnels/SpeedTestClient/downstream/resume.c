#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    ls->send_paused = false;
    speedtestclientScheduleSend(t, l, ls);
}

