#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestClient: upstream Pause is disabled");
    terminateProgram(1);
}

