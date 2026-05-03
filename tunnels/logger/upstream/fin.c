#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    if (t->next == NULL)
    {
        return;
    }

    tunnelNextUpStreamFinish(t, l);
}
