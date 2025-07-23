#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    
    lineMarkEstablished(l);
}
