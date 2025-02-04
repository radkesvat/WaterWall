#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpListener: upStreamPause disabled");
    assert(false);
}

