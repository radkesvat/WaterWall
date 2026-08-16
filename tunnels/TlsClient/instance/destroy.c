#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
