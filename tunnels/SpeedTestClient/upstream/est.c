#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestClient: upstream Est is disabled");
    terminateProgram(1);
}

