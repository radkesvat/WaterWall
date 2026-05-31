#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestServer: downstream Pause is disabled");
    terminateProgram(1);
}

