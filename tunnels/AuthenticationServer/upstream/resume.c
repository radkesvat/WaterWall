#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    ls->response_paused = false;
    discard authenticationserverFlushResponses(t, l, ls);
}
