#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpOverUdpServer: UpstreamEst is disabled");
    abortProgramNow(1);
}
