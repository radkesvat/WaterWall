#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    if (junkdatagramsenderIsWorkerPacketLine(t, l))
    {
        return;
    }

    tunnelNextUpStreamFinish(t, l);
}
