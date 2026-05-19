#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    discard l;

    if (! ts->packet_mode)
    {
        LOGF("TesterServer: downStreamEst disabled");
        assert(false);
        return;
    }
}
