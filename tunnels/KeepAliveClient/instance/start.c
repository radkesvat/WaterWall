#include "structure.h"

#include "loggers/network_logger.h"

static void keepaliveclientStartWorkerTimer(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    worker_t                 *worker = worker_ptr;
    tunnel_t                 *t      = arg1;
    keepaliveclient_tstate_t *ts     = tunnelGetState(t);

    if (UNLIKELY(isApplicationTerminating()))
    {
        return;
    }

    wtimer_t *timer = wtimerAdd(worker->loop, keepaliveclientWorkerTimerCallback, ts->ping_interval_ms, INFINITE);
    if (timer == NULL)
    {
        LOGF("KeepAliveClient: failed to create periodic keepalive timer on worker %u", (unsigned int) worker->wid);
        terminateProgram(1);
        return;
    }

    weventSetUserData(timer, t);
    ts->worker_timers[worker->wid] = timer;
}

void keepaliveclientTunnelOnStart(tunnel_t *t)
{
    for (wid_t wi = 0; wi < getWorkersCount(); ++wi)
    {
        sendWorkerMessageForceQueue(wi, keepaliveclientStartWorkerTimer, t, NULL, NULL);
    }
}
