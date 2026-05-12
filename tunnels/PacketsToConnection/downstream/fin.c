#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    ptcCloseLineFromDownstream(t, l);
}
