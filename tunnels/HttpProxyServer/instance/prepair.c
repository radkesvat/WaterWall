#include "loggers/network_logger.h"
#include "structure.h"

void httpproxyserverTunnelOnPrepair(tunnel_t *t)
{
    hps_tstate_t *ts = tunnelGetState(t);
    if (ts->auth_mode == kHpsAuthTracked)
    {
        ts->auth = ts->auth_node->instance;
        if (! ts->auth)
        {
            LOGF("HttpProxyServer: AuthenticationClient instance unavailable");
            startupFailureRecord(1);
        }
    }
}
