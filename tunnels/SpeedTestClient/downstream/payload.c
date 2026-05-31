#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    speedtestclientProcessIncoming(t, l, buf);
}

