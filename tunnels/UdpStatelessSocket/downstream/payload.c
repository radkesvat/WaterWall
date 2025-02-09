#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) t;
    (void) l;
    (void) buf;
    LOGF("This Function is disabled, this node is up end adapter");
    exit(1);
}
