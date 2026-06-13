#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->k_handle == NULL))
    {
        return;
    }

    if (UNLIKELY(! ls->can_upstream))
    {
        // re-entrant finish from prev side while our DownStreamFinish is flushing the close
        // frame; destroying the state makes that flush stop and not touch prev side again
        tcpoverudpserverLinestateDestroy(ls);
        return;
    }

    tcpoverudpserverLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
