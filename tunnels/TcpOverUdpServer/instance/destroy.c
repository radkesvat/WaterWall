#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

