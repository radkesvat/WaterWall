#include "structure.h"

#include "loggers/network_logger.h"

void pingserverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // Local reverse-direction data becomes a fresh Echo Request toward PingClient.
    pingserverHandleDownstreamPacket(t, l, buf);
}
