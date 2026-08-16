#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseserver_tstate_t *ts = tunnelGetState(t);
    reverseclientHandshakeDestroy(ts->handshake_bytes);
    tunnelDestroy(t);
}
