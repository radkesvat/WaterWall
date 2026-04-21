#include "structure.h"

#include "loggers/network_logger.h"

static void testerclientStartWorker(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t                    *real_worker = worker;
    tunnel_t                    *t           = arg1;
    wid_t                        wid         = real_worker->wid;
    testerclient_tstate_t       *ts          = tunnelGetState(t);
    line_t                      *l           = ts->packet_mode
                                                   ? tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid)
                                                   : lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    testerclient_lstate_t       *ls          = lineGetState(l, t);
    testerclient_worker_state_t *slot = &ts->workers[wid];

    discard arg2;
    discard arg3;

    testerclientLinestateInitialize(ls, lineGetBufferPool(l));
    ls->flow_id = (uint8_t) wid;
    slot->line = l;
    slot->completed = false;

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        if (ts->packet_mode)
        {
            LOGF("TesterClient: packet line died during packet-mode init");
            terminateProgram(1);
        }
        return;
    }

    lineScheduleDelayedTask(l, testerclientWatchdogTask, kTesterClientWatchdogMs, t);
}

void testerclientTunnelOnStart(tunnel_t *t)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        sendWorkerMessageTimed(wi, testerclientStartWorker, kTesterClientStartDelayMs, t, NULL, NULL);
    }
}
