#include "structure.h"

#include "loggers/network_logger.h"

void ping6serverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // Local reverse-direction data becomes a fresh Echo Request toward Ping6Client.
    ping6serverHandleDownstreamPacket(t, l, buf);
}
