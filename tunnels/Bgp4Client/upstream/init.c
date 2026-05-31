#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    bgp4clientLinestateInitialize(lineGetState(l, t), l);

    tunnelNextUpStreamInit(t, l);
}
