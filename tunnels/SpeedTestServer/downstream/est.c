#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestServer: downstream Est is disabled");
    terminateProgram(1);
}

