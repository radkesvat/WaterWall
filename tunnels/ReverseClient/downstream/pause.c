#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    reverseclient_lstate_t *uls = lineGetState(l, t);
    tunnelPrevDownStreamPause(t, uls->d);
}
