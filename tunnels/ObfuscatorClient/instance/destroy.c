#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

