#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

