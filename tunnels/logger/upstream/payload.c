#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard l;

    loggertunnelHandlePayload(t, buf, true);

    if (t->next == NULL)
    {
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
