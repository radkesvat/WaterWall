#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->k_handle != NULL);

    if (UNLIKELY(! ls->can_upstream))
    {
        // finish from prev side while our close frame is flushing or queued data is still being delivered;
        // destroying the state stops that close without touching prev side again
        tcpoverudpserverLinestateDestroy(ls);
        return;
    }

    tcpoverudpserverLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
