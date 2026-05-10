#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("PacketSender: upStreamInit disabled");
    terminateProgram(1);
}

