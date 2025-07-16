#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

