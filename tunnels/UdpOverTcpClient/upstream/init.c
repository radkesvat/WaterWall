#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);
    udpovertcpclientLinestateInitialize(ls, lineGetBufferPool(l));
    
    tunnelNextUpStreamInit(t, l);
}
