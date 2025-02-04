#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamInit(t, l);
}
