#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    testerclient_tstate_t *ts = tunnelGetState(t);
    testerclient_lstate_t *ls = lineGetState(l, t);

    if (ts->packet_mode)
    {
        // Category D: a worker packet line lives for the whole process, so a
        // Finish on it is a packet-line contract violation, not a test verdict.
        LOGF("TesterClient: packet-mode received unexpected finish on worker packet line");
        abortProgramNow(1);
    }

    if (! ls->response_complete)
    {
        testerclientFail(t, l, "received finish before full response verification");
        return;
    }

    testerclientLinestateDestroy(ls);
    testerclientMarkWorkerComplete(t, l);

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }
}
