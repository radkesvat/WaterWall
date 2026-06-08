#include "structure.h"

#include "loggers/network_logger.h"

static void udpstatelesssocketStopIo(udpstatelesssocket_tstate_t *state)
{
    wio_t *io = state->io;
    if (io == NULL)
    {
        return;
    }

    state->io = NULL;
    if (getTID() == getWorker(state->io_wid)->tid && getWorker(state->io_wid)->loop != NULL)
    {
        wioClose(io);
    }
}

void udpstatelesssocketTunnelOnStop(tunnel_t *t)
{
    udpstatelesssocketStopIo(tunnelGetState(t));
}
