#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpListener: upStreamEst disabled");
    assert(false);
}
