#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnStart(tunnel_t *t)
{
    for (wid_t i = 0; i < getWorkersCount() - WORKER_ADDITIONS; i++)
    {
        line_t *l = tunnelchainGetPacketLine(tunnelGetChain(t), i);

        tunnelNextUpStreamInit(t, l);
        assert(lineIsAlive(l));
     
    }
}
