#include "structure.h"

void trojanserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    if (t == NULL)
    {
        return;
    }

    trojanserverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
