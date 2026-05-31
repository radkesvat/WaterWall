#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestClient: upstream Init is disabled");
    terminateProgram(1);
}

