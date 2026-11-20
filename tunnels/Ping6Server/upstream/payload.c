#include "structure.h"

#include "loggers/network_logger.h"

void ping6serverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // Wrapped requests from Ping6Client are restored toward Ping6Server's next node.
    ping6serverHandleUpstreamPacket(t, l, buf);
}
