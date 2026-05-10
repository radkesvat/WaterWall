#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("PacketSender: upStreamEst disabled");
    terminateProgram(1);
}

