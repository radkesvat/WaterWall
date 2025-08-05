#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamEst(t, l);
}
