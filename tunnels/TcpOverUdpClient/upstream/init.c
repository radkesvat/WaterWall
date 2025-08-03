#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    tcpoverudpclientLinestateInitialize(ls, l, t);

    tunnelNextUpStreamInit(t, l);
}
