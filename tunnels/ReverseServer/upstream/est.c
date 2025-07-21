#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelUpStreamEst(tunnel_t *t, line_t *d)
{
    discard t;
    discard d;

    LOGF("reverseserverTunnelUpStreamEst: Upstream Est is disabled");
    terminateProgram(1);
}

