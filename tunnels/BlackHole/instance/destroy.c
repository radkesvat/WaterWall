#include "structure.h"

#include "loggers/network_logger.h"

void blackholeTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
