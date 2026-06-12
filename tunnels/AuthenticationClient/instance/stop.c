#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationclientDeleteTimer(wtimer_t **timer)
{
    if (*timer == NULL)
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
}

void authenticationclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    if (wid != 0)
    {
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    authenticationclientDeleteTimer(&ts->ping_timer);
    authenticationclientDeleteTimer(&ts->sync_timer);
    authenticationclientDeleteTimer(&ts->reconnect_timer);

    line_t *line = NULL;
    mutexLock(&ts->control_mutex);
    line = ts->control_line;
    mutexUnlock(&ts->control_mutex);

    if (line != NULL && lineIsAlive(line))
    {
        authenticationclientCloseControlLine(t, line, true);
    }
}
