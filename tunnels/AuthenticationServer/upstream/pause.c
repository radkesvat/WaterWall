#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    ls->response_paused = true;
    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream paused downstream response writes");
    }
}
