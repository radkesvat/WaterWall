#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    trojanclientTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
