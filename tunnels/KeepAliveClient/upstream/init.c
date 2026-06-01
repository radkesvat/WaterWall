#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);
    keepaliveclientLinestateInitialize(ls, l);
    keepaliveclientTrackLine(t, l);

    tunnelNextUpStreamInit(t, l);
}
