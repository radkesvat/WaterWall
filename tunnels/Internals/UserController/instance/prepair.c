#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelOnPrepair(tunnel_t *t)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);

    unsigned mode_sources =
        (ts->fixed_payload_mode != 0) + (ts->payload_mode_resolver != NULL) + ts->payload_mode_from_destination;
    if (mode_sources != 1)
    {
        LOGF("UserController: declare payload-mode or bind one creator mode resolver, exclusively");
        startupFailureRecord(1);
        return;
    }
    ts->prepared = true;

    if (ts->auth_client_node == NULL)
    {
        LOGF("UserController: auth-client-node-name was not resolved during create");
        startupFailureRecord(1);
        return;
    }

    ts->auth_client_tunnel = ts->auth_client_node->instance;
    if (ts->auth_client_tunnel == NULL)
    {
        LOGF("UserController: AuthenticationClient node \"%s\" instance is not available", ts->auth_client_node->name);
        startupFailureRecord(1);
        return;
    }
}
