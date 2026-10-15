#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    udpstatelesssocket_lstate_t *ls = lineGetState(l, t);
    if (udpstatelesssocketLinestateOwnsLine(ls))
    {
        ls->read_paused = true;
    }
}
