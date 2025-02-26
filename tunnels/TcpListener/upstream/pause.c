#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpListener: upStreamPause disabled");
    assert(false);
}

