#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    discard t;
    ls->send_paused = true;
}

