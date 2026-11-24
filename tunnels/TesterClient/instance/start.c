#include "structure.h"

#include "loggers/network_logger.h"

#ifdef WW_TESTERCLIENT_START_TEST_SEAM
void testerclientStartWorkerTestInvoke(worker_t *worker, tunnel_t *t);
#endif

void testerclientStartLine(tunnel_t *t, line_t *l)
{
    const wid_t                  wid         = lineGetWID(l);
    testerclient_tstate_t       *ts          = tunnelGetState(t);
    testerclient_lstate_t       *ls          = lineGetState(l, t);
    testerclient_worker_state_t *slot        = &ts->workers[wid];

    assert(lineIsOnCurrentWorker(l));
    assert(ts->packet_mode == tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    // A peer head can initialize this packet line first through a Bridge.
    if (ls->read_stream.pool == NULL)
    {
        testerclientLinestateInitialize(ls, lineGetBufferPool(l));
    }
    ls->flow_id           = (uint8_t) wid;
    slot->line            = l;
    slot->completed       = false;
    slot->close_scheduled = false;
    slot->closed          = false;

    if (! ts->packet_mode || ts->initial_dest_context_enabled)
    {
        addresscontextCopy(lineGetDestinationAddressContext(l), &ts->initial_dest_context);
    }

    if (ts->packet_mode && ts->packet_start_immediately)
    {
        // Startup owns the first send, even if Init synchronously reports Est or Resume.
        ls->request_send_scheduled = true;
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

    if (! ts->packet_mode)
    {
        if (! wloopNormalDispatchAllowed(getWorkerLoop(wid)))
        {
            return;
        }
        ls->request_ready = true;
        if (! ls->request_paused && ! testerclientScheduleRequestSend(t, l, ls))
        {
            return;
        }
    }
    else if (ts->packet_start_immediately)
    {
        ls->request_ready = true;
        if (ts->packet_start_delay_ms > 0)
        {
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
            ls->request_send_scheduled = false;
            if (! testerclientScheduleRequestSend(t, l, ls))
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

static void testerclientStartWorker(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t *owner = worker;
    tunnel_t *t     = arg1;
    discard   arg2;
    discard   arg3;
    line_t   *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), owner->wid);
    testerclientStartLine(t, l);
}

#ifdef WW_TESTERCLIENT_START_TEST_SEAM
void testerclientStartWorkerTestInvoke(worker_t *worker, tunnel_t *t)
{
    testerclientStartWorker(worker, t, NULL, NULL);
}
#endif

void testerclientTunnelOnStart(tunnel_t *t)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        if (UNLIKELY(sendWorkerMessageTimedRetainOnRefusal(
                         wi, testerclientStartWorker, NULL, kTesterClientStartDelayMs, t, NULL, NULL) !=
                     kWorkerMessageSubmitAccepted))
        {
            startupFailureRecord(1);
            return;
        }
    }
}
