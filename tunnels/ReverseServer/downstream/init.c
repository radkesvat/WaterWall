#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamInit(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *uls = lineGetState(u, t);
    reverseserverLinestateInitialize(uls, u, NULL);
    tunnelNextUpStreamEst(t, u);
    
}
