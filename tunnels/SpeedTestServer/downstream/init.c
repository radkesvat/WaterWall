#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestServer: downstream Init is disabled");
    terminateProgram(1);
}

