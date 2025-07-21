#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    reverseserver_lstate_t *ls = lineGetState(l, t);

    tunnelPrevDownStreamResume(t, ls->d);
}
