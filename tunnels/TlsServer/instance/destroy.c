#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    tlsserverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
