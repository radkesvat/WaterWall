#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

