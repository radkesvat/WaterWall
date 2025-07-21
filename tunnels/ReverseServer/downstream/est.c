#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamEst(tunnel_t *t, line_t *u)
{
    discard t;
    discard u;

    LOGF("ReverseServer: Downstream Est is disabled");
    terminateProgram(1);
}
