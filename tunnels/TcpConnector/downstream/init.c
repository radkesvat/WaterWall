#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpConnector: downStreamInit disabled");
    assert(false);
}
