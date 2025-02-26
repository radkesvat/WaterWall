#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
    LOGF("TcpListener: upStreamPayload disabled");
    assert(false);
}
