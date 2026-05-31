#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    if (! lineIsEstablished(l))
    {
        lineMarkEstablished(l);
    }

    tunnelPrevDownStreamEst(t, l);
}
