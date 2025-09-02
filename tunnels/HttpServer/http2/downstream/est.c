#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamEst(t, l);
}
