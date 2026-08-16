#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    encryptionserver_tstate_t *ts = tunnelGetState(t);
    encryptionserverTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
