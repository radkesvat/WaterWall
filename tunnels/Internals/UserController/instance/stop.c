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

void usercontrollerTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void usercontrollerTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_states == NULL || wid >= ts->worker_count)
    {
        return;
    }

    usercontrollerDeleteTimer(&ts->worker_states[wid].sweep_timer);
    usercontrollerWorkerClearRegistry(t, wid);
}
