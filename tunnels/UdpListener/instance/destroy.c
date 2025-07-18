#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

