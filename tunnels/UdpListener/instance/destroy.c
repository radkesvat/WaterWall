#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard               context;
    udplistener_tstate_t *state = tunnelGetState(t);

    if (state->listen_address != NULL)
    {
        memoryFree(state->listen_address);
    }

    tunnelDestroy(t);
}
