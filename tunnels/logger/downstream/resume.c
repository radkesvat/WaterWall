#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    if (t->prev == NULL)
    {
        return;
    }

    tunnelPrevDownStreamResume(t, l);
}
