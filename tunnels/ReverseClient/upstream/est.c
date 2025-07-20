#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    lineMarkEstablished(l);
}
