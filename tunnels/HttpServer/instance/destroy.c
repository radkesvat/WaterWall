#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

