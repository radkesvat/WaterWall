#include "structure.h"

#include "loggers/network_logger.h"

void ping6clientDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ping6clientDecapsulatePacket(t, l, buf);
}
