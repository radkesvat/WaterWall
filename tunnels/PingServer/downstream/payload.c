#include "structure.h"

#include "loggers/network_logger.h"

void pingserverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // Server-side inbound request path: wrapped packets from next are restored toward prev.
    pingserverHandleInboundPacket(t, l, buf);
}
