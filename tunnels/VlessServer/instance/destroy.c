#include "structure.h"

void vlessserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    if (t == NULL)
    {
        return;
    }

    vlessserverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
