#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->can_upstream))
    {
        return;
    }
    tunnelNextUpStreamPause(t, l);
}
