#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelOnStart(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: starting timers on worker 0");
    }

    if (LIKELY(ts->save_timer == NULL))
    {
        ts->save_timer =
            wtimerAdd(getWorkerLoop(0), authenticationserverSaveTimerCallback, ts->file_save_rate_ms, INFINITE);
        if (UNLIKELY(ts->save_timer == NULL))
        {
            LOGF("AuthenticationServer: failed to create periodic save timer");
            terminateProgram(1);
            return;
        }

        weventSetUserData(ts->save_timer, t);
        LOGI("AuthenticationServer: periodic users database save enabled every %u ms", ts->file_save_rate_ms);
    }

    if (LIKELY(ts->session_expiry_timer == NULL))
    {
        ts->session_expiry_timer = wtimerAdd(getWorkerLoop(0),
                                             authenticationserverSessionExpiryTimerCallback,
                                             kAuthenticationServerSessionExpirySweepMs,
                                             INFINITE);
        if (UNLIKELY(ts->session_expiry_timer == NULL))
        {
            LOGF("AuthenticationServer: failed to create session expiry timer");
            terminateProgram(1);
            return;
        }

        weventSetUserData(ts->session_expiry_timer, t);
        LOGI("AuthenticationServer: session expiry check enabled every %u ms",
             (unsigned int) kAuthenticationServerSessionExpirySweepMs);
    }
}
