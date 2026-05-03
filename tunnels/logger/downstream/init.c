#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    if (t->prev == NULL)
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}
