#include "structure.h"

#include "loggers/network_logger.h"

static void usercontrollerDeleteTimer(wtimer_t **timer)
{
    if (*timer == NULL)
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

void usercontrollerTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void usercontrollerTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_states == NULL || wid >= ts->worker_count)
    {
        return;
    }

    usercontrollerDeleteTimer(&ts->worker_states[wid].sweep_timer);
}

void usercontrollerTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_states == NULL || wid >= ts->worker_count)
    {
        return;
    }
    usercontrollerWorkerClearRegistry(t, wid);
}
