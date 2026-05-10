#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("PacketSender: upStreamPause disabled");
    terminateProgram(1);
}

