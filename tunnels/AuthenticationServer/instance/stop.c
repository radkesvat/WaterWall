#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationserverDeleteTimer(wtimer_t **timer)
{
    if (UNLIKELY(*timer == NULL))
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

void authenticationserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    if (UNLIKELY(wid != 0))
    {
        return;
    }

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (ts->verbose)
    {
        LOGD("AuthenticationServer: worker 0 stopping; deleting save and session-expiry timers");
    }

    authenticationserverDeleteTimer(&ts->save_timer);
    authenticationserverDeleteTimer(&ts->session_expiry_timer);
}
