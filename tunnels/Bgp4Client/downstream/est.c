#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamEst(t, l);
}
