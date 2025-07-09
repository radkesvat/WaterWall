#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    // if this direction is used to change ip adderss, see helpers.h and init.c
    // otherwise pass through
    tunnelNextUpStreamPayload(t, l, buf);
}
