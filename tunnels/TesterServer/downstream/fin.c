#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Category D in both branches: the packet-mode branch would mean a persistent
 * worker packet line was finished at runtime, and in stream mode this node is
 * the chain end, so there is no next tunnel that could ever send a downstream
 * Finish. Neither is a peer-selectable verdict.
 */
void testerserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    discard l;

    if (ts->packet_mode)
    {
        LOGF("TesterServer: packet-mode received unexpected downstream finish on worker packet line");
        abortProgramNow(1);
    }

    LOGF("TesterServer: downStreamFinish disabled");
    abortProgramNow(1);
}
