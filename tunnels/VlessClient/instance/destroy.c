#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    vlessclientTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
