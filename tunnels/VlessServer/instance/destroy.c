#include "structure.h"

void vlessserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(t != NULL);

    vlessserverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
