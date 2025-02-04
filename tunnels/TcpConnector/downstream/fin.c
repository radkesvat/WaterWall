#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpConnector: downStreamFinish disabled");
    assert(false);
}
