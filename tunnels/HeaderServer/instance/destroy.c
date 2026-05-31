#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
