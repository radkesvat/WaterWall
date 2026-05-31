#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestClient: upstream Resume is disabled");
    terminateProgram(1);
}

