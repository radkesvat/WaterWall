#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    // Borrowed transport and packet lines need no per-line state at this endpoint.
}
