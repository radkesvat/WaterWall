#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestServer: upstream Est is disabled");
    terminateProgram(1);
}

