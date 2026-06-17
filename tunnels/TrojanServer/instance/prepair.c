#include "structure.h"

#include "loggers/network_logger.h"

void trojanserverTunnelOnPrepair(tunnel_t *t)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (ts->auth_client_node == NULL)
    {
        LOGF("TrojanServer: auth-client-node-name was not resolved during create");
        terminateProgram(1);
    }

    ts->auth_client_tunnel = ts->auth_client_node->instance;
    if (ts->auth_client_tunnel == NULL)
    {
        LOGF("TrojanServer: AuthenticationClient node \"%s\" instance is not available", ts->auth_client_node->name);
        terminateProgram(1);
    }
}
