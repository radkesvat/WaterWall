#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestServer: downstream Resume is disabled");
    terminateProgram(1);
}

