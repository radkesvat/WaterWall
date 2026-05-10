#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("PacketSender: upStreamFinish disabled");
    terminateProgram(1);
}

