#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpstatelesssocketTunnelWritePayload(t, l, buf);
}
