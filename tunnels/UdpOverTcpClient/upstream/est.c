#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpOverTcpClient: UpstreamEst is disabled");
    terminateProgram(1);
}
