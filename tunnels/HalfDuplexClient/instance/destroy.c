#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

