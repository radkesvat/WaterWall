#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("TcpConnector: upStreamEst is not supposed to be called");
    exit(1);
}
