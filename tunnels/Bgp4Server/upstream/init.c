#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    bgp4serverLinestateInitialize(lineGetState(l, t), l);

    tunnelNextUpStreamInit(t, l);
}
