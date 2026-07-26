#include "structure.h"

#include "loggers/network_logger.h"

void pingserverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // Wrapped requests from PingClient are restored toward PingServer's next node.
    pingserverHandleUpstreamPacket(t, l, buf);
}
