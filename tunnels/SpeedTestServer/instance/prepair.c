#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelOnPrepair(tunnel_t *t)
{
    if (t->prev == NULL)
    {
        LOGF("SpeedTestServer: must have a previous transport tunnel");
        terminateProgram(1);
    }

    if (t->next != NULL)
    {
        LOGF("SpeedTestServer: must be the end of a connection speed-test chain");
        terminateProgram(1);
    }
}

