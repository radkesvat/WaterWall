#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDestroy(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (state->io)
    {
        wioClose(state->io);
    }

    if (state->listen_address)
    {
        memoryFree(state->listen_address);
    }
    mutexDestroy(&state->mutex);

    tunnelDestroy(t);
}
