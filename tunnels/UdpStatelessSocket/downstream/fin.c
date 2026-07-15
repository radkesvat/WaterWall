#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    udpstatelesssocketCloseOwnedLineFromAdjacent(t, l, false);
}
