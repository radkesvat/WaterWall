#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SpeedTestClient: downstream Init is disabled");
    terminateProgram(1);
}

