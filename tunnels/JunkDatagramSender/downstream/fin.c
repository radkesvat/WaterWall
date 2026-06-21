#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    if (junkdatagramsenderIsWorkerPacketLine(t, l))
    {
        return;
    }

    tunnelPrevDownStreamFinish(t, l);
}
