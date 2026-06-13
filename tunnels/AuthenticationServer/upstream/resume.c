#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    ls->response_paused = false;
    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream resumed downstream response writes");
    }
    discard authenticationserverFlushResponses(t, l, ls);
}
