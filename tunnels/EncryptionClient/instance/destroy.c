#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    encryptionclient_tstate_t *ts = tunnelGetState(t);
    encryptionclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
