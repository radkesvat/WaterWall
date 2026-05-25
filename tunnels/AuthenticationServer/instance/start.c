#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelOnStart(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (ts->save_timer != NULL)
    {
        return;
    }

    ts->save_timer = wtimerAdd(getWorkerLoop(0), authenticationserverSaveTimerCallback, ts->file_save_rate_ms, INFINITE);
    if (ts->save_timer == NULL)
    {
        LOGF("AuthenticationServer: failed to create periodic save timer");
        terminateProgram(1);
        return;
    }

    weventSetUserData(ts->save_timer, t);
    LOGI("AuthenticationServer: periodic users database save enabled every %u ms", ts->file_save_rate_ms);
}
