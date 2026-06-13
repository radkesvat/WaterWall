#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    if (LIKELY(! lineIsEstablished(l)))
    {
        lineMarkEstablished(l);
    }

    mutexLock(&ts->control_mutex);
    if (LIKELY(ts->control_line == l))
    {
        ts->connected = true;
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: downstream transport established; sending Authenticate");
        }
    }
    mutexUnlock(&ts->control_mutex);

    discard authenticationclientSendAuthenticate(t);
}
