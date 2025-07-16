#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    // discarding
    discard t;
    discard l;
    // This function is disabled, but this node is bidirectional, so just ignore it
}
