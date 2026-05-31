#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
