#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserverV2LinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
