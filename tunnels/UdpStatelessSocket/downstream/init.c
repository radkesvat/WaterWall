#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is disabled, this node is up end adapter");
    terminateProgram(1);
}
