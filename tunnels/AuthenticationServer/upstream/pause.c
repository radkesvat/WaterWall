#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    discard t;
    ls->response_paused = true;
}
