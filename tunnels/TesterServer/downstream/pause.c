#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    testerserver_lstate_t *ls = lineGetState(l, t);

    if (! ts->packet_mode)
    {
        LOGF("TesterServer: downStreamPause disabled");
        abortProgramNow(1);
    }

    ls->response_paused = true;
}
