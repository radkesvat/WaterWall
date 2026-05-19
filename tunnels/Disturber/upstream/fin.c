#include "structure.h"

#include "loggers/network_logger.h"

void disturberTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    if (disturberIsWorkerPacketLine(t, l))
    {
        return;
    }

    disturber_lstate_t *ls = lineGetState(l, t);
    disturberLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
