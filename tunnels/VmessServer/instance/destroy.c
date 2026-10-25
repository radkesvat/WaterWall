#include "internal.h"

void vmessserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(t != NULL);

    nodeApiUnregister(t);
    vmessserverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
