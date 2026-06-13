#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationclientStartOnWorker0(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t *worker = worker_ptr;
    tunnel_t *t      = arg1;

    discard arg2;
    discard arg3;

    if (UNLIKELY(isApplicationTerminating()))
    {
        return;
    }
    if (UNLIKELY(worker->wid != 0))
    {
        LOGF("AuthenticationClient: startup control task ran on worker %u", (unsigned int) worker->wid);
        terminateProgram(1);
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->control_mutex);
    ts->started  = true;
    ts->stopping = false;
    mutexUnlock(&ts->control_mutex);

    if (ts->ping_interval_ms > 0 && LIKELY(ts->ping_timer == NULL))
    {
        ts->ping_timer = wtimerAdd(worker->loop, authenticationclientPingTimerCallback, ts->ping_interval_ms, INFINITE);
        if (UNLIKELY(ts->ping_timer == NULL))
        {
            LOGF("AuthenticationClient: failed to create ping timer");
            terminateProgram(1);
            return;
        }
        weventSetUserData(ts->ping_timer, t);
    }

    authenticationclientStartSyncTimer(t);

    authenticationclientOpenControlLine(t);
}

void authenticationclientTunnelOnStart(tunnel_t *t)
{
    sendWorkerMessageForceQueue(0, authenticationclientStartOnWorker0, t, NULL, NULL);
}
