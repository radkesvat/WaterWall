#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    testerserver_lstate_t *ls = lineGetState(l, t);
    const char            *failure_reason;

    if (ts->packet_mode)
    {
        // Category D: a worker packet line lives for the whole process, so a
        // Finish on it is a packet-line contract violation, not a test verdict.
        LOGF("TesterServer: packet-mode received unexpected finish on worker packet line");
        abortProgramNow(1);
    }

    if (ls->request_rx_index != testerserverGetChunkCount(t) || ! ls->response_ready)
    {
        failure_reason = "received finish before full request verification";
    }
    else if (! ls->response_sent)
    {
        failure_reason = "received finish before sending the full response sequence";
    }
    else
    {
        testerserverLinestateDestroy(ls);
        return;
    }

    // Finish is terminal for this endpoint. Orderly process shutdown may defer
    // line reclamation, but this callback must not leave live per-line state.
    testerserverLinestateDestroy(ls);
    testerserverFail(t, l, failure_reason);
}
