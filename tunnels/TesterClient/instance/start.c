#include "structure.h"

#include "loggers/network_logger.h"

static void testerclientStartWorker(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t                    *real_worker = worker;
    tunnel_t                    *t           = arg1;
    wid_t                        wid         = real_worker->wid;
    testerclient_tstate_t       *ts          = tunnelGetState(t);
    line_t                      *l           = ts->packet_mode ? tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid)
                                                               : lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    testerclient_lstate_t       *ls          = lineGetState(l, t);
    testerclient_worker_state_t *slot        = &ts->workers[wid];

    discard arg2;
    discard arg3;

    testerclientLinestateInitialize(ls, lineGetBufferPool(l));
    ls->flow_id           = (uint8_t) wid;
    slot->line            = l;
    slot->completed       = false;
    slot->close_scheduled = false;
    slot->closed          = false;

    if (ts->initial_dest_context_enabled)
    {
        addresscontextCopy(lineGetDestinationAddressContext(l), &ts->initial_dest_context);
    }

    if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
    {
        if (ts->packet_mode)
        {
            LOGF("TesterClient: packet line died during packet-mode init");
            abortProgramNow(1);
        }
        return;
    }

    if (ts->packet_mode && ts->packet_start_immediately)
    {
        ls->est_received = true;
        if (ts->packet_start_delay_ms > 0)
        {
            ls->request_send_scheduled = true;
            if (UNLIKELY(! lineScheduleDelayedTask(l, testerclientRequestSendTask, ts->packet_start_delay_ms, t)))
            {
                ls->request_send_scheduled = false;
                testerclientFail(t, l, "failed to schedule packet-mode request start");
                return;
            }
        }
        else
        {
            testerclientScheduleRequestSend(t, l, ls);
        }
    }

    if (UNLIKELY(! lineScheduleDelayedTask(l, testerclientWatchdogTask, kTesterClientWatchdogMs, t)))
    {
        if (ts->packet_mode)
        {
            testerclientFail(t, l, "failed to arm watchdog");
        }
        else
        {
            testerclientFailOwnedLine(t, l, "failed to arm watchdog", true);
        }
    }
}

static void testerclientCleanupStartWorker(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg1;
    discard arg2;
    discard arg3;
    if (reason != kWorkerMessageCancelResourceFailure)
    {
        return;
    }
    LOGE("TesterClient: worker start task failed after admission");
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

void testerclientTunnelOnStart(tunnel_t *t)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        if (UNLIKELY(sendWorkerMessageTimedRetainOnRefusal(wi,
                                                           testerclientStartWorker,
                                                           testerclientCleanupStartWorker,
                                                           kTesterClientStartDelayMs,
                                                           t,
                                                           NULL,
                                                           NULL) != kWorkerMessageSubmitAccepted))
        {
            startupFailureRecord(1);
            return;
        }
    }
}
