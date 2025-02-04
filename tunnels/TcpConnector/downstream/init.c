#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpConnector: downStreamInit disabled");
    assert(false);
}
