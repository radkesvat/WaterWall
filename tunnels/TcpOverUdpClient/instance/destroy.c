#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

