#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

