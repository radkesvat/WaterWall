#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    // packet tunnels dont care about this callabck
    (void) t;
    (void) l;
}
