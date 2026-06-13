#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationclientDeleteTimer(wtimer_t **timer)
{
    if (UNLIKELY(*timer == NULL))
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

void authenticationclientTunnelOnStop(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->control_mutex);
    ts->stopping = true;
    mutexUnlock(&ts->control_mutex);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: stop requested");
    }
}

void authenticationclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    if (UNLIKELY(wid != 0))
    {
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: worker 0 stopping; deleting timers and closing control line if needed");
    }

    authenticationclientDeleteTimer(&ts->ping_timer);
    authenticationclientDeleteTimer(&ts->sync_timer);
    authenticationclientDeleteTimer(&ts->reconnect_timer);

    line_t *line = NULL;
    mutexLock(&ts->control_mutex);
    line = ts->control_line;
    mutexUnlock(&ts->control_mutex);

    if (LIKELY(line != NULL && lineIsAlive(line)))
    {
        authenticationclientCloseControlLine(t, line, true);
    }
}
