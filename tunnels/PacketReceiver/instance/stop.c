#include "structure.h"

#include "loggers/network_logger.h"

void packetreceiverTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}
