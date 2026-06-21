#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
