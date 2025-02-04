#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpListener: upStreamResume disabled");
    assert(false);
}
