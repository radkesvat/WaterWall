#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TcpConnector: upStreamEst is not supposed to be called");
    exit(1);
}
