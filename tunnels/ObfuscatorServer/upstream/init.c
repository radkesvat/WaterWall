#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
