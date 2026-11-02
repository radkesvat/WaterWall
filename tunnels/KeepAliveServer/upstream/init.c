#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    keepaliveserverLinestateInitialize(ls, l, tunnelGetChain(t)->supports_splice);

    tunnelNextUpStreamInit(t, l);
}
