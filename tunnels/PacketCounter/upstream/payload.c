#include "structure.h"

#include "loggers/network_logger.h"

void packetcounterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetcounterHandlePacket(t, l, buf);
}
