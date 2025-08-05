#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamInit(t, l);
}
