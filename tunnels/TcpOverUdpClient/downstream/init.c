#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpOverUdpClient: DownStreamInit is disabled");
    terminateProgram(1);
}
