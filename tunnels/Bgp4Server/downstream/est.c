#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamEst(t, l);
}
