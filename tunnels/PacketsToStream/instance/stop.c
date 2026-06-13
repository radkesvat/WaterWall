#include "structure.h"

#include "loggers/network_logger.h"

static void packetstostreamDeleteTimer(wtimer_t **timer)
{
    if (*timer == NULL)
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

void packetstostreamTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void packetstostreamTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    packetstostream_tstate_t *ts = tunnelGetState(t);

    if (ts->worker_timers != NULL)
    {
        packetstostreamDeleteTimer(&ts->worker_timers[wid]);
    }

    if (ts->worker_timeout_timers != NULL)
    {
        packetstostreamDeleteTimer(&ts->worker_timeout_timers[wid]);
    }
}
