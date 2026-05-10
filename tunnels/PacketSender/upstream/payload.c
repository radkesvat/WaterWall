#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
    LOGF("PacketSender: upStreamPayload disabled");
    terminateProgram(1);
}

