#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);

    httpserverV2LinestateInitialize(ls, t, lineGetWID(l));

    tunnelNextUpStreamInit(t, l);

}
