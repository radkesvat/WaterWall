#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpConnector: downStreamPause disabled");
}
