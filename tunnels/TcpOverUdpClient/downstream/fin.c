#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{

    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->k_handle == NULL))
    {
        return;
    }

    if (UNLIKELY(! ls->can_downstream))
    {
        // re-entrant finish from next side while our UpStreamFinish is flushing the close
        // frame; destroying the state makes that flush stop and not touch next side again
        tcpoverudpclientLinestateDestroy(ls);
        return;
    }

    tcpoverudpclientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
