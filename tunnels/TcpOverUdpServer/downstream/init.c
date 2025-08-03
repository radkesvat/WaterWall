#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpOverUdpServer: DownStreamInit is disabled");
    terminateProgram(1);
}
