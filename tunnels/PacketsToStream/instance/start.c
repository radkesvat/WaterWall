#include "structure.h"

#include "loggers/network_logger.h"

static void packetstostreamStartWorkerTimer(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    worker_t                 *worker = worker_ptr;
    tunnel_t                 *t      = arg1;
    packetstostream_tstate_t *ts     = tunnelGetState(t);

    if (UNLIKELY(isApplicationTerminating()))
    {
        return;
    }

    wtimer_t *timer = wtimerAdd(worker->loop, packetstostreamHeartbeatTimerCallback, ts->interval_ms, INFINITE);
    if (timer == NULL)
    {
        LOGF("PacketsToStream: failed to create sensitive-mode timer on worker %u", (unsigned int) worker->wid);
        terminateProgram(1);
        return;
    }

    weventSetUserData(timer, t);
    ts->worker_timers[worker->wid] = timer;
}

void packetstostreamTunnelOnStart(tunnel_t *t)
{
    packetstostream_tstate_t *ts = tunnelGetState(t);

    if (! ts->sensitive_mode)
    {
        return;
    }

    for (wid_t wi = 0; wi < getWorkersCount(); ++wi)
    {
        sendWorkerMessageForceQueue(wi, packetstostreamStartWorkerTimer, t, NULL, NULL);
    }
}
