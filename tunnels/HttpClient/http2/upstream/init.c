#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelUpStreamInit(tunnel_t *t, line_t *l)
{

    httpclient_lstate_t *ls = lineGetState(l, t);

    httpclientV2LinestateInitialize(ls, t, lineGetWID(l));

    tunnelNextUpStreamInit(t, l);

}
