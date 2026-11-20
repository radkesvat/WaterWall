#include "structure.h"

#include "loggers/network_logger.h"

void ping6clientUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ping6clientEncapsulatePacket(t, l, buf);
}
