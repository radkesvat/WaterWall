#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
