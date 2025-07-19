#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpConnector: DownStream Est is disabled");
    terminateProgram(1);
}
