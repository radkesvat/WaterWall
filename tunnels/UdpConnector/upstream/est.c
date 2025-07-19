#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpConnector: UpStream Est is disabled");
    terminateProgram(1);
}
