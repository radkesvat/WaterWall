#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelOnStart(tunnel_t *t)
{
    // in general the node manager sends init for chains that conain packet nodes
    // but since the starter adapter of the chain is Not a packet node, we need to send init for all workers

    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
    {
        line_t *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wi);

        tunnelNextUpStreamInit(t, l);
        assert(lineIsAlive(l));
    }
}
