#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (t->next == NULL)
    {
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
