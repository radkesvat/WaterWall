#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, l, buf);
}
