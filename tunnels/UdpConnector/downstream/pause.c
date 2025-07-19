#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpConnector: DownStream Pause is disabled");
    terminateProgram(1);
}
