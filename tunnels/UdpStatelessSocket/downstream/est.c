#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    udpstatelesssocket_lstate_t *ls = lineGetState(l, t);
    if (udpstatelesssocketLinestateOwnsLine(ls))
    {
        lineMarkEstablished(l);
    }
}
