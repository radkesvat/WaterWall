#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    lineLock(l);
    tunnelNextUpStreamInit(t, l);

    if (lineIsAlive(l))
    {
        discard junkdatagramsenderSendInitialJunk(t, l, kJunkDatagramSenderDirectionUpstream);
    }

    lineUnlock(l);
}
