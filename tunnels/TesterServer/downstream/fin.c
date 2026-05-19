#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (ts->packet_mode)
    {
        testerserverFail(t, l, "packet-mode received unexpected downstream finish on worker packet line");
        return;
    }

    LOGF("TesterServer: downStreamFinish disabled");
    assert(false);
}
