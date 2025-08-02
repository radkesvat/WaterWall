#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpOverTcpClient: DownStreamInit is disabled");

    terminateProgram(1);
}
