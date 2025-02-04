#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpListener: upStreamInit disabled");
    assert(false);
}
