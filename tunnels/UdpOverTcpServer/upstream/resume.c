#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    if (! ls->upstream_initialized)
    {
        return;
    }

    tunnelNextUpStreamResume(t, l);
}
