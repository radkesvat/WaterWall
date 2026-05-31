#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    speedtestserverProcessIncoming(t, l, buf);
}

