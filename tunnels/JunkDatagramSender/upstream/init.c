#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (! junkdatagramsenderIsWorkerPacketLine(t, l))
    {
        junkdatagramsender_tstate_t *ts = tunnelGetState(t);
        junkdatagramsender_lstate_t *ls = lineGetState(l, t);
        junkdatagramsenderLinestateInitialize(ls, ts);
    }

    tunnelNextUpStreamInit(t, l);
}
