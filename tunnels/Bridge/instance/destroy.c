#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

