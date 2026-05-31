#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestServer: downstream Finish is disabled");
    terminateProgram(1);
}

