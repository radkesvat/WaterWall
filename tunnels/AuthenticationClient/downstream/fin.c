#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    authenticationclient_tstate_t *ts               = tunnelGetState(t);
    bool                           should_reconnect = false;

    mutexLock(&ts->control_mutex);
    should_reconnect = ts->started && ! ts->stopping && ts->control_line == l;
    mutexUnlock(&ts->control_mutex);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: downstream transport finished; reconnect=%s",
             should_reconnect ? "true" : "false");
    }

    authenticationclientCloseControlLine(t, l, false);

    if (LIKELY(should_reconnect))
    {
        authenticationclientScheduleReconnect(t);
    }
}
