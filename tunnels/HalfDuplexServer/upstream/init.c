#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    halfduplexserverLinestateInitialize(ls);

    tunnelPrevDownStreamEst(t, l);

}
