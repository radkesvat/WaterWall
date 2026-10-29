#include "structure.h"

#include "loggers/network_logger.h"

void packetgeneratorTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetgeneratorHandleUnexpectedDownstreamPayload(t, l, buf);
}
