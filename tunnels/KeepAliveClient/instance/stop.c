#include "structure.h"

#include "loggers/network_logger.h"

static void keepaliveclientDeleteTimer(wtimer_t **timer)
{
    if (*timer == NULL)
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

void keepaliveclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_timers == NULL)
    {
        return;
    }

    keepaliveclientDeleteTimer(&ts->worker_timers[wid]);
}
