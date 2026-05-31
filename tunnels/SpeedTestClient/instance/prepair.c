#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelOnPrepair(tunnel_t *t)
{
    tunnel_chain_t *chain = tunnelGetChain(t);

    if (t->next == NULL)
    {
        LOGF("SpeedTestClient: must have a next transport tunnel");
        terminateProgram(1);
    }

    if (chain == NULL || chain->workers_count == 0)
    {
        LOGF("SpeedTestClient: chain has zero workers");
        terminateProgram(1);
    }
}

