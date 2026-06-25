#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    if (! ls->upstream_initialized)
    {
        return;
    }

    tunnelNextUpStreamPause(t, l);
}
