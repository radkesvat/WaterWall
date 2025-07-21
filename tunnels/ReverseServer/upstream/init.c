#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelUpStreamInit(tunnel_t *t, line_t *d)
{
    reverseserver_lstate_t *dls = lineGetState(d, t);

    line_t *dl = d;

    reverseserverLinestateInitialize(dls, NULL, dl);

    tunnelPrevDownStreamEst(t, dl);
}
