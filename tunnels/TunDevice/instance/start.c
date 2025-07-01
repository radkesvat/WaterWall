#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnStart(tunnel_t *t)
{
    for (wid_t i = 0; i < getWorkersCount(); i++)
    {
        line_t *l = tunnelchainGetPacketLine(tunnelGetChain(t), i);

        lineLock(l);
        tunnelNextUpStreamInit(t, l);
        if (! lineIsAlive(l))
        {
            LOGF("TunDevice: line is not alive, rule of packet tunnels is violated during line initialization");
            terminateProgram(1);
        }
        lineUnlock(l);
    }
}
