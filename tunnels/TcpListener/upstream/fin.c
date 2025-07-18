#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpListener: upStreamFinish disabled");
    terminateProgram(1);
}
