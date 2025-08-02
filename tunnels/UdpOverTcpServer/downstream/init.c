#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpOverTcpServer: DownStreamInit is disabled");

    terminateProgram(1);
}
