#include "structure.h"

#include "loggers/network_logger.h"

static void keepaliveclientStartWorkerTimer(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    worker_t                 *worker = worker_ptr;
    tunnel_t                 *t      = arg1;
    keepaliveclient_tstate_t *ts     = tunnelGetState(t);

    wtimer_t *timer = wtimerAdd(worker->loop, keepaliveclientWorkerTimerCallback, ts->ping_interval_ms, INFINITE);
    if (timer == NULL)
    {
        LOGF("KeepAliveClient: failed to create periodic keepalive timer on worker %u", (unsigned int) worker->wid);
        /*
         * Category B: this task was enqueued by onStart but runs on a worker
         * event loop, so it must not tear anything down itself. The timer slot
         * stays NULL; timers other workers already published are deleted by
         * their own onWorkerStop during the orderly shutdown.
         */
        if (! requestProgramShutdown(1))
        {
            abortProgramNow(1);
        }
        return;
    }

    weventSetUserData(timer, t);
    ts->worker_timers[worker->wid] = timer;
}

void keepaliveclientTunnelOnStart(tunnel_t *t)
{
    for (wid_t wi = 0; wi < getWorkersCount(); ++wi)
    {
        if (UNLIKELY(sendWorkerMessageForceQueueWithCleanup(wi, keepaliveclientStartWorkerTimer, NULL, t, NULL, NULL) !=
                     kWorkerMessageSubmitAccepted))
        {
            LOGF("KeepAliveClient: failed to admit required timer startup on worker %u", (unsigned int) wi);
            startupFailureRecord(1);
            return;
        }
    }
}
