#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelUpStreamPause(tunnel_t *t, line_t *d)
{
    reverseserver_lstate_t *dls = lineGetState(d, t);

    tunnelNextUpStreamPause(t, dls->u);
}
