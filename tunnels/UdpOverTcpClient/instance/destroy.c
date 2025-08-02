#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

