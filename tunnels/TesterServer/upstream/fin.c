#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    testerserver_lstate_t *ls = lineGetState(l, t);

    if (ts->packet_mode)
    {
        // Category D: a worker packet line lives for the whole process, so a
        // Finish on it is a packet-line contract violation, not a test verdict.
        LOGF("TesterServer: packet-mode received unexpected finish on worker packet line");
        abortProgramNow(1);
    }

    if (ls->request_rx_index != testerserverGetChunkCount(t) || ! ls->response_ready)
    {
        testerserverFail(t, l, "received finish before full request verification");
        return;
    }

    if (! ls->response_sent)
    {
        testerserverFail(t, l, "received finish before sending the full response sequence");
        return;
    }

    testerserverLinestateDestroy(ls);
}
