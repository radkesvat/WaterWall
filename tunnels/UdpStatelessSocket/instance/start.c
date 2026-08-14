#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnStart(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    assert(state->socket.io != NULL);
    assert(state->io_wid == 0);
    assert(currentThreadIsEventWorkerWID(state->io_wid));
    if (UNLIKELY(! tunnelasyncsessionOpen(state->async_session)))
    {
        LOGF("UdpStatelessSocket: async callback session was opened more than once");
        abortProgramNow(1);
    }
}
