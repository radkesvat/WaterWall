#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    testerserver_lstate_t *ls = lineGetState(l, t);

    if (! ts->packet_mode)
    {
        LOGF("TesterServer: downStreamInit disabled");
        assert(false);
        return;
    }

    if (ls->read_stream.pool == NULL)
    {
        testerserverLinestateInitialize(ls, lineGetBufferPool(l));
    }

    ls->response_to_next = true;
    tunnelNextUpStreamEst(t, l);
}
