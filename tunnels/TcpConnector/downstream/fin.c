#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpConnector: downStreamFinish disabled");
    assert(false);
}
