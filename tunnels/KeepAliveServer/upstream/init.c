#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    keepaliveserverLinestateInitialize(ls, l);
    if (ls->read_stream == NULL)
    {
        keepaliveserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
