#include "structure.h"

#include "loggers/network_logger.h"

void vlessserverTunnelOnPrepair(tunnel_t *t)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);

    if (ts->auth_client_node == NULL)
    {
        return;
    }

    ts->auth_client_tunnel = ts->auth_client_node->instance;
    if (ts->auth_client_tunnel == NULL)
    {
        LOGF("VlessServer: AuthenticationClient node \"%s\" instance is not available", ts->auth_client_node->name);
        terminateProgram(1);
    }
}
