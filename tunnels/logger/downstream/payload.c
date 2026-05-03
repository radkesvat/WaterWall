#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard l;

    loggertunnelHandlePayload(t, buf, false);

    if (t->prev == NULL)
    {
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
