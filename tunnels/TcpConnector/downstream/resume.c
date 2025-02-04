#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpConnector: downStreamResume disabled");
    assert(false);
}
