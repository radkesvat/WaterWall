#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    udpovertcpserverLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
}
