#include "structure.h"

#include "loggers/network_logger.h"

void blackholeTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    if (t->next == NULL)
    {
        return;
    }
    tunnelNextUpStreamEst(t, l);
}
