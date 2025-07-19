#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpConnector: DownStream Finish is disabled");
    terminateProgram(1);
}
