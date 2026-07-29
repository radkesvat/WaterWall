#include "structure.h"

#include "loggers/network_logger.h"

void ptcDestroyLwipResources(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    if (state->lwip_resources_destroyed)
    {
        return;
    }

    LOCK_TCPIP_CORE();
    ptcDestroyRouteContexts(&state->route_context4);
    ptcDestroyRouteContexts(&state->route_context6);
    ptcFakeDnsDestroy(state);
    state->lwip_resources_destroyed = true;
    UNLOCK_TCPIP_CORE();
}

void ptcTunnelDestroy(tunnel_t *t)
{
    ptcDestroyLwipResources(t);

    tunnelDestroy(t);
}
