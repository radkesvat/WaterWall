#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
