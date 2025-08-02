#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    udpovertcpserverLinestateDestroy(ls);
    
    tunnelPrevDownStreamFinish(t, l);
}
