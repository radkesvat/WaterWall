#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    // packet tunnels dont care about this callabck
    discard t;
    discard l;
}
