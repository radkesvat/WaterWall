#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpOverUdpClient: UpstreamEst is disabled");
    terminateProgram(1);
}
