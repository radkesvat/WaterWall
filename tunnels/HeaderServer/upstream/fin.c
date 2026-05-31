#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    headerserverCloseLineFromUpstream(t, l);
}
