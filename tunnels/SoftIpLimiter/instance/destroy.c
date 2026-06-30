#include "structure.h"

void softiplimiterTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    softiplimiterTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}

