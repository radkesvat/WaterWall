#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    tunnelDestroy(t);
}
