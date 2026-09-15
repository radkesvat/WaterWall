#include "structure.h"

#include "loggers/network_logger.h"

#ifdef WW_TESTERCLIENT_START_TEST_SEAM
void testerclientStartWorkerTestInvoke(worker_t *worker, tunnel_t *t);
#endif

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
            const line_task_submit_result_e result =
                lineScheduleDelayedTask(l, testerclientRequestSendTask, ts->packet_start_delay_ms, t, NULL);
            if (UNLIKELY(result == kLineTaskSubmitRejectedSettled))
            {
                ls->request_send_scheduled = false;
                testerclientFail(t, l, "failed to schedule packet-mode request start");
                return;
            }
            assert(result == kLineTaskSubmitTimerArmed);
        }
        else
        {
            testerclientScheduleRequestSend(t, l, ls);
            /* Force-queued work cannot run before this owner callback returns,
             * so a clear latch here means synchronous admission rejection.
             * testerclientScheduleRequestSend() already recorded the terminal
             * verdict; do not arm fresh watchdog work after that request. */
            if (UNLIKELY(! ls->request_send_scheduled))
            {
                return;
            }
        }
    }

    const line_task_submit_result_e watchdog_result =
        lineScheduleDelayedTask(l, testerclientWatchdogTask, kTesterClientWatchdogMs, t, NULL);
    if (UNLIKELY(watchdog_result == kLineTaskSubmitRejectedSettled))
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
    else
    {
        assert(watchdog_result == kLineTaskSubmitTimerArmed);
    }
}

#ifdef WW_TESTERCLIENT_START_TEST_SEAM
void testerclientStartWorkerTestInvoke(worker_t *worker, tunnel_t *t)
{
    testerclientStartWorker(worker, t, NULL, NULL);
}
#endif

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
