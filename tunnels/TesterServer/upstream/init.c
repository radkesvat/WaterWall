#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    testerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->read_stream.pool == NULL)
    {
        testerserverLinestateInitialize(ls, lineGetBufferPool(l));
    }
    tunnelPrevDownStreamEst(t, l);
}
