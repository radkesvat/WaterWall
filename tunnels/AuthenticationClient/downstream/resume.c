#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->control_mutex);
    if (LIKELY(ts->control_line == l))
    {
        ts->write_paused = false;
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: downstream resumed control writes; retrying Authenticate if needed");
        }
    }
    mutexUnlock(&ts->control_mutex);

    discard authenticationclientSendAuthenticate(t);
}
