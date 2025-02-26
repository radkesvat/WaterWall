#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpConnector: downStreamPause disabled");
}
