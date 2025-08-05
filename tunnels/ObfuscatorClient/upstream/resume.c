#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamResume(t, l);
}
