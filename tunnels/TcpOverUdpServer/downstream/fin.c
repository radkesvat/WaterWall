#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    tcpoverudpserverLinestateDestroy(ls);
    
    tunnelPrevDownStreamFinish(t, l);
}
