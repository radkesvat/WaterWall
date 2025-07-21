#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{

    reverseserver_lstate_t *ls = lineGetState(l, t);
    tunnelPrevDownStreamPause(t, ls->d);
}
