#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    if (junkdatagramsenderIsWorkerPacketLine(t, l))
    {
        return;
    }

    junkdatagramsender_lstate_t *ls = lineGetState(l, t);
    junkdatagramsenderLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);
}
