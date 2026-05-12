#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDestroy(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    LOCK_TCPIP_CORE();
    ptcDestroyRouteContexts(&state->route_context4);
    ptcDestroyRouteContexts(&state->route_context6);
    ptcFakeDnsDestroy(state);
    UNLOCK_TCPIP_CORE();

    tunnelDestroy(t);
}
