#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("This Function is disabled, this node is up end adapter");
    exit(1);
}
