#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->can_downstream))
    {
        return;
    }
    tunnelPrevDownStreamResume(t, l);
}
