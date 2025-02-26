#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is disabled, this node is up end adapter");
    exit(1);}
