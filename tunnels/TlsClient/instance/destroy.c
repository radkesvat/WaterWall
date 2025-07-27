#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

