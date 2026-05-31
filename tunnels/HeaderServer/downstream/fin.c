#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    headerserverCloseLineFromDownstream(t, l);
}
