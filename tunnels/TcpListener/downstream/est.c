#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    lineMarkEstablished(l);
}
