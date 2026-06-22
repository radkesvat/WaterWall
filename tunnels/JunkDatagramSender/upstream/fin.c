#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    if (junkdatagramsenderIsWorkerPacketLine(t, l))
    {
        return;
    }

    junkdatagramsender_lstate_t *ls = lineGetState(l, t);
    junkdatagramsenderLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
