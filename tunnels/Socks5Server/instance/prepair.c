#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelOnPrepair(tunnel_t *t)
{
    socks5server_tstate_t *ts = tunnelGetState(t);

    if (ts->auth_client_node == NULL)
    {
        LOGF("Socks5Server: auth-client-node-name was not resolved during create");
        terminateProgram(1);
    }

    ts->auth_client_tunnel = ts->auth_client_node->instance;
    if (ts->auth_client_tunnel == NULL)
    {
        LOGF("Socks5Server: AuthenticationClient node \"%s\" instance is not available",
             ts->auth_client_node->name);
        terminateProgram(1);
    }
}
