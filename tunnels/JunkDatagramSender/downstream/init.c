#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    if (! junkdatagramsenderSelectTransport(t, l))
    {
        tunnelNextUpStreamFinish(t, l);
        return;
    }

    junkdatagramsender_tstate_t *ts = tunnelGetState(t);
    junkdatagramsender_lstate_t *ls = lineGetState(l, t);
    junkdatagramsenderLinestateInitialize(ls, ts);

    tunnelPrevDownStreamInit(t, l);
}
