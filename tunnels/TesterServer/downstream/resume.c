#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    testerserver_lstate_t *ls = lineGetState(l, t);

    if (! ts->packet_mode)
    {
        LOGF("TesterServer: downStreamResume disabled");
        assert(false);
        return;
    }

    ls->response_paused = false;
    testerserverScheduleResponseSend(t, l, ls);
}
