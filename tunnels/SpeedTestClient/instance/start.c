#include "structure.h"

#include "loggers/network_logger.h"

static void speedtestclientStartStream(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t *real_worker = worker;
    tunnel_t *t = arg1;
    uint32_t *stream_id_ptr = arg2;
    uint32_t stream_id = *stream_id_ptr;
    speedtestclient_tstate_t *state = tunnelGetState(t);

    discard arg3;
    memoryFree(stream_id_ptr);

    line_t *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), real_worker->wid);
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    speedtestclientLinestateInitialize(ls, t, l, stream_id);

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        return;
    }

    lineScheduleDelayedTask(l, speedtestclientWatchdogTask, state->timeout_ms, t);
}

void speedtestclientTunnelOnStart(tunnel_t *t)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    speedtestclient_tstate_t *state = tunnelGetState(t);

    for (uint32_t stream_id = 0; stream_id < state->connection_count; ++stream_id)
    {
        uint32_t *stream_id_ptr = memoryAllocate(sizeof(*stream_id_ptr));
        if (stream_id_ptr == NULL)
        {
            LOGF("SpeedTestClient: failed to allocate startup stream id");
            terminateProgram(1);
            return;
        }
        *stream_id_ptr = stream_id;

        wid_t wid = (wid_t) (stream_id % chain->workers_count);
        sendWorkerMessageTimed(wid, speedtestclientStartStream, state->start_delay_ms, t, stream_id_ptr, NULL);
    }
}

