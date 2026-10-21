#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnStart(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    discard                      state;
    assert(state->socket.io != NULL);
    assert(state->io_wid == 0);
    assert(currentThreadOwnsWorker(state->io_wid));
}
