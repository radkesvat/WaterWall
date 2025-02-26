#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpListener: upStreamResume disabled");
    assert(false);
}
