#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    udpstatelesssocket_lstate_t *ls = lineGetState(l, t);
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (udpstatelesssocketLinestateOwnsLine(t, l, ls) && ! state->is_chain_end)
    {
        ls->read_paused = false;
    }
}
