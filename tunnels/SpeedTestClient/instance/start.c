#include "structure.h"

#include "loggers/network_logger.h"

static void speedtestclientStartStream(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t                 *real_worker   = worker;
    tunnel_t                 *t             = arg1;
    uint32_t                 *stream_id_ptr = arg2;
    uint32_t                  stream_id     = *stream_id_ptr;
    speedtestclient_tstate_t *state         = tunnelGetState(t);

    discard arg3;
    memoryFree(stream_id_ptr);

    if (atomicLoadRelaxed(&state->stopping))
    {
        return;
    }

    line_t                   *l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), real_worker->wid);
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    speedtestclientLinestateInitialize(ls, t, l, stream_id);
    assert(state->owned_lines[stream_id] == NULL);
    state->owned_lines[stream_id] = l;
    ls->upstream_init_sent        = true;

    if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
    {
        return;
    }

    const line_task_submit_result_e result =
        lineScheduleDelayedTask(l, speedtestclientWatchdogTask, state->timeout_ms, t, NULL);
    if (UNLIKELY(result == kLineTaskSubmitRejectedSettled))
    {
        speedtestclientFailLine(t, l, "failed to arm watchdog");
    }
    else
    {
        assert((state->timeout_ms == 0 && result == kLineTaskSubmitAcceptedAsync) ||
               (state->timeout_ms > 0 && result == kLineTaskSubmitTimerArmed));
    }
}

static void speedtestclientCleanupStartStream(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    tunnel_t                 *t     = arg1;
    speedtestclient_tstate_t *state = tunnelGetState(t);
    discard                   arg3;

    memoryFree(arg2);
    if (atomicLoadRelaxed(&state->stopping))
    {
        return;
    }
    if (reason != kWorkerMessageCancelResourceFailure)
    {
        return;
    }
    LOGF("SpeedTestClient: delayed stream creation failed after admission");
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static void speedtestclientRequiredStartFailure(const char *reason)
{
    LOGF("SpeedTestClient: %s", reason);
    startupFailureRecord(1);
}

void speedtestclientTunnelOnStart(tunnel_t *t)
{
    tunnel_chain_t           *chain = tunnelGetChain(t);
    speedtestclient_tstate_t *state = tunnelGetState(t);

    for (uint32_t stream_id = 0; stream_id < state->connection_count; ++stream_id)
    {
        uint32_t *stream_id_ptr = memoryAllocate(sizeof(*stream_id_ptr));
        if (stream_id_ptr == NULL)
        {
            speedtestclientRequiredStartFailure("failed to allocate startup stream id");
            return;
        }
        *stream_id_ptr = stream_id;

        wid_t wid = (wid_t) (stream_id % chain->workers_count);
        if (UNLIKELY(sendWorkerMessageTimedRetainOnRefusal(wid,
                                                           speedtestclientStartStream,
                                                           speedtestclientCleanupStartStream,
                                                           state->start_delay_ms,
                                                           t,
                                                           stream_id_ptr,
                                                           NULL) != kWorkerMessageSubmitAccepted))
        {
            memoryFree(stream_id_ptr);
            if (! atomicLoadRelaxed(&state->stopping))
            {
                startupFailureRecord(1);
            }
            return;
        }
    }
}
