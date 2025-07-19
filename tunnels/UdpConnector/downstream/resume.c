#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpConnector: DownStream Resume is disabled");
    terminateProgram(1);
}
