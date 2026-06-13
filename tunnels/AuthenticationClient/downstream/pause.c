#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->control_mutex);
    if (LIKELY(ts->control_line == l))
    {
        ts->write_paused = true;
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: downstream paused control writes");
        }
    }
    mutexUnlock(&ts->control_mutex);
}
