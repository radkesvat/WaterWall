#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    testerserver_lstate_t *ls = lineGetState(l, t);

    ls->response_paused = true;
}
