#include "structure.h"

#include "loggers/network_logger.h"

void pingserverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // Server-side outbound response path: plain packets from prev are wrapped toward next.
    pingserverHandleOutboundPacket(t, l, buf);
}
