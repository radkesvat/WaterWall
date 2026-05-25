#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    authenticationserverLinestateInitialize(ls, lineGetBufferPool(l));
    tunnelPrevDownStreamEst(t, l);
}
