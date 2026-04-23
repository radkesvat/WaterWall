#include "structure.h"

#include "loggers/network_logger.h"

void packetsplitstreamTunnelOnPrepair(tunnel_t *t)
{
    packetsplitstream_tstate_t *ts = tunnelGetState(t);
    if (ts->up_tunnel == NULL || ts->down_tunnel == NULL)
    {
        LOGF("PacketSplitStream: onPrepare called but up or down tunnel is not set "
        "(up: %s, down: %s)", ts->up_tunnel ? "set" : "not set", ts->down_tunnel ? "set" : "not set");
        terminateProgram(1);
        return;
    }

    ts->up_tunnel->onPrepare(ts->up_tunnel);
    ts->down_tunnel->onPrepare(ts->down_tunnel);
}

