#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpListener: upStreamInit disabled");
    terminateProgram(1);
}
