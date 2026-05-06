#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpstatelesssocketTunnelWritePayload(t, l, buf);
}
