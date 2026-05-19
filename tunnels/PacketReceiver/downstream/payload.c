#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetreceiverHandlePacket(t, l, buf);
}
