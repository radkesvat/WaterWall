#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamPause(t, l);
}
