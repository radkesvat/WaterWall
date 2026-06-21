#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    lineLock(l);
    tunnelPrevDownStreamInit(t, l);

    if (lineIsAlive(l))
    {
        discard junkdatagramsenderSendInitialJunk(t, l, kJunkDatagramSenderDirectionDownstream);
    }

    lineUnlock(l);
}
