#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    reverseclient_lstate_t *dls = lineGetState(l, t);
    tunnelNextUpStreamPause(t, dls->u);
}
