#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Category B (orderly runtime failure). This runs on the worker-0 event loop
 * long after startup handed control to the workers, so the ping timer failing
 * is a runtime resource failure, not a main-thread startup failure. Nothing is
 * owned here besides the timer that was never created: request an orderly
 * shutdown and report the failure so the caller stops the startup sequence.
 */
static bool authenticationclientStartPingTimer(worker_t *worker, tunnel_t *t, authenticationclient_tstate_t *ts)
{
    if (ts->ping_interval_ms == 0 || UNLIKELY(ts->ping_timer != NULL))
    {
        return true;
    }

    ts->ping_timer = wtimerAdd(worker->loop, authenticationclientPingTimerCallback, ts->ping_interval_ms, INFINITE);
    if (UNLIKELY(ts->ping_timer == NULL))
    {
        LOGF("AuthenticationClient: failed to create ping timer");
        if (! requestProgramShutdown(1))
        {
            abortProgramNow(1);
        }
        return false;
    }

    weventSetUserData(ts->ping_timer, t);
    if (ts->verbose)
    {
        LOGD("AuthenticationClient: ping timer enabled every %u ms", (unsigned int) ts->ping_interval_ms);
    }

    return true;
}

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
        abortProgramNow(1);
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->control_mutex);
    ts->started  = true;
    ts->stopping = false;
    mutexUnlock(&ts->control_mutex);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: startup control task running on worker 0");
    }

    if (! authenticationclientStartPingTimer(worker, t, ts))
    {
        return;
    }

    if (! authenticationclientStartSyncTimer(t))
    {
        return;
    }

    authenticationclientOpenControlLine(t);
}

void authenticationclientTunnelOnStart(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (ts->verbose)
    {
        LOGD("AuthenticationClient: queueing startup control task on worker 0");
    }

    if (UNLIKELY(! sendWorkerMessageForceQueueWithCleanup(0, authenticationclientStartOnWorker0, NULL, t, NULL, NULL)))
    {
        LOGF("AuthenticationClient: failed to admit required worker-0 startup control task");
        terminateProgram(1);
    }
}
