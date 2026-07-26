#include "structure.h"

#include "loggers/network_logger.h"

void pingserverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // Plain responses from PingServer's next node are wrapped toward PingClient.
    pingserverHandleDownstreamPacket(t, l, buf);
}
