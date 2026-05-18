#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    disturberTunnelPayload(t, l, buf, kDisturberPayloadDirectionDownstream);
}
