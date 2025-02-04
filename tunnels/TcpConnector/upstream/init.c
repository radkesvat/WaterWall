#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
