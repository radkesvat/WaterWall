#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpConnector: DownStream Init is disabled");
    terminateProgram(1);
}
