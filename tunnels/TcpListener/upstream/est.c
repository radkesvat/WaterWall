#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpListener: upStreamEst disabled");
    assert(false);
}
