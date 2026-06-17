#include "structure.h"

void trojanserverTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    trojanserverTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
