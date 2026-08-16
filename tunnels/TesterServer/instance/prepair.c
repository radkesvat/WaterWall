#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelOnPrepair(tunnel_t *t)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (ts->packet_mode && tunnelGetChain(t)->packet_lines == NULL)
    {
        LOGF("TesterServer: packet-mode requires packet lines; add a packet-layer tunnel in the chain");
        startupFailureRecord(1);
        return;
    }
}
