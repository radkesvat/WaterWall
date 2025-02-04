#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpListener: upStreamFinish disabled");
    assert(false);
}
