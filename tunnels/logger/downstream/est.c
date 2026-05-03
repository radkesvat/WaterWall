#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    if (t->prev == NULL)
    {
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}
