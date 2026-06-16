#include "structure.h"

#include "loggers/network_logger.h"

static void usercontrollerStartWorkerTimer(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    worker_t                *worker = worker_ptr;
    tunnel_t                *t      = arg1;
    usercontroller_tstate_t *ts     = tunnelGetState(t);

    if (UNLIKELY(isApplicationTerminating()))
    {
        return;
    }

    wtimer_t *timer = wtimerAdd(worker->loop, usercontrollerSweepTimerCallback, ts->sweep_interval_ms, INFINITE);
    if (timer == NULL)
    {
        LOGF("UserController: failed to create sweep timer on worker %u", (unsigned int) worker->wid);
        terminateProgram(1);
        return;
    }

    weventSetUserData(timer, t);
    ts->worker_states[worker->wid].sweep_timer = timer;
}

void usercontrollerTunnelOnStart(tunnel_t *t)
{
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        sendWorkerMessageForceQueue(wid, usercontrollerStartWorkerTimer, t, NULL, NULL);
    }
}
