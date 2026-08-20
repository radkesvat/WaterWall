#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(t != NULL);

    socks5serverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
