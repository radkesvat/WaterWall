#include "structure.h"

void vlessserverTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    vlessserverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
