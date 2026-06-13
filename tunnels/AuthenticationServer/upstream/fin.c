#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream Finish; destroying authentication line state");
    }

    authenticationserverLinestateDestroy(ls);
}
