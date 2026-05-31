#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
