#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpOverTcpServer: UpstreamEst is disabled");
    terminateProgram(1);
}
