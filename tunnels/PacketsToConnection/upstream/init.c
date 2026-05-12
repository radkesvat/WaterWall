#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    // init from packt to connection is blocking and is normally called from those nodes at startup
}
