#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) t;
    (void) l;
    (void) buf;
    LOGF("TcpListener: upStreamPayload disabled");
    assert(false);
}
