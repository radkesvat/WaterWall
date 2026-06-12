#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationserverDeleteTimer(wtimer_t **timer)
{
    if (*timer == NULL)
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

void authenticationserverTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void authenticationserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    if (wid != 0)
    {
        return;
    }

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserverDeleteTimer(&ts->save_timer);
    authenticationserverDeleteTimer(&ts->session_expiry_timer);
}
