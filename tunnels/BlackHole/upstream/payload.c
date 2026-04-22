#include "structure.h"

#include "loggers/network_logger.h"

void blackholeTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
}
