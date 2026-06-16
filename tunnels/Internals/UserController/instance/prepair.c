#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelOnPrepair(tunnel_t *t)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);

    if (ts->auth_client_node == NULL)
    {
        LOGF("UserController: auth-client-node-name was not resolved during create");
        terminateProgram(1);
    }

    ts->auth_client_tunnel = ts->auth_client_node->instance;
    if (ts->auth_client_tunnel == NULL)
    {
        LOGF("UserController: AuthenticationClient node \"%s\" instance is not available", ts->auth_client_node->name);
        terminateProgram(1);
    }
}
