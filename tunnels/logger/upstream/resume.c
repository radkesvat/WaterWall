#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    if (t->next == NULL)
    {
        return;
    }

    tunnelNextUpStreamResume(t, l);
}
