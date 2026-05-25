#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    authenticationserverLinestateDestroy(ls);
}
