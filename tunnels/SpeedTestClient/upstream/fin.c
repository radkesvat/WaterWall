#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestClient: upstream Finish is disabled");
    terminateProgram(1);
}

