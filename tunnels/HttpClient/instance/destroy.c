#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

