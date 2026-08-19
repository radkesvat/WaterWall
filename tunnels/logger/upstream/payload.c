#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    loggertunnelHandlePayload(t, buf, true);

    tunnelNextUpStreamPayload(t, l, buf);
}
