#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDestroy(tunnel_t *t)
{
    reverseserver_tstate_t *ts = tunnelGetState(t);
    reverseclientHandshakeDestroy(ts->handshake_bytes);
    tunnelDestroy(t);
}
