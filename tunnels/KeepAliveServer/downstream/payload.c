#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveserverSendNormalFrameDownstream(t, l, buf);
}
