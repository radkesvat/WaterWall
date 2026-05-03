#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    if (t->prev == NULL)
    {
        return;
    }

    tunnelPrevDownStreamFinish(t, l);
}
