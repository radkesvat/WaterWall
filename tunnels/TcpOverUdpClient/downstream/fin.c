#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{

    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->can_downstream))
    {
        return;
    }
    tcpoverudpclientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
