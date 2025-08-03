#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    tcpoverudpserverLinestateInitialize(ls, l, t);

    tunnelNextUpStreamInit(t, l);
}
