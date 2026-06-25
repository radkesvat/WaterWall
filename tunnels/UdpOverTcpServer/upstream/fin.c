#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    bool upstream_initialized = ls->upstream_initialized;

    udpovertcpserverLinestateDestroy(ls);

    if (upstream_initialized)
    {
        tunnelNextUpStreamFinish(t, l);
    }
}
