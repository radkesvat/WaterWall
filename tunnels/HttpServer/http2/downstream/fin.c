#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserverV2LinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
