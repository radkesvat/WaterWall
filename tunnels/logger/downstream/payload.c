#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    loggertunnelHandlePayload(t, buf, false);

    tunnelPrevDownStreamPayload(t, l, buf);
}
