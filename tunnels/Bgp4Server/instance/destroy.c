#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    tunnelDestroy(t);
}
