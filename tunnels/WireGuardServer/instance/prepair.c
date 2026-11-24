#include "WireGuardServer/structure.h"
#include "loggers/network_logger.h"

void wireguardserverTunnelOnPrepare(tunnel_t *t)
{
    server_t *state      = tunnelGetState(t);
    state->ingress_heads = memoryAllocateZero(sizeof(*state->ingress_heads) * t->chain->workers_count);
    if (state->connection)
    {
        state->auth = state->auth_node->instance;
        if (state->auth == NULL)
        {
            LOGF("WireGuardServer: AuthenticationClient service is unavailable");
            startupFailureRecord(1);
        }
    }
}
