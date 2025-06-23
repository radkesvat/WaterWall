#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

