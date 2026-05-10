#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetsenderHandleUnexpectedDownstreamPayload(t, l, buf);
}

