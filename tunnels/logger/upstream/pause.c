#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    if (t->next == NULL)
    {
        return;
    }

    tunnelNextUpStreamPause(t, l);
}
