#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamEst(t, l);
}
