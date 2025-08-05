#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

