#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

