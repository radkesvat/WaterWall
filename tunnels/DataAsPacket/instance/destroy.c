#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

