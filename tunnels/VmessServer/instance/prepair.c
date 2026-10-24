#include "internal.h"

#include "loggers/network_logger.h"

void vmessserverTunnelOnPrepair(tunnel_t *t)
{
    vmessserver_tstate_t *ts = tunnelGetState(t);

    if (ts->auth_client_node == NULL)
    {
        return;
    }

    ts->auth_client_tunnel = ts->auth_client_node->instance;
    if (ts->auth_client_tunnel == NULL)
    {
        LOGF("VmessServer: AuthenticationClient node \"%s\" instance is not available", ts->auth_client_node->name);
        startupFailureRecord(1);
        return;
    }
}
