#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpConnector: downStreamResume disabled");
    assert(false);
}
