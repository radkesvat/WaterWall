#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);
    usercontroller_lstate_t *ls = lineGetState(l, t);

    usercontrollerLinestateInitialize(ls);

    const user_handle_t *current = lineGetCurrentUser(l);

    // Only authenticated lines are subject to limits. Anonymous/no-auth lines pass through untouched.
    if (current != NULL && userHandleIsValid(current))
    {
        ls->handle        = *current;
        ls->authenticated = true;
        usercontrollerBuildIpKey(l, &ls->ip_key);

        user_admission_result_t result = authenticationclientUserTryAdmitConnection(
            ts->auth_client_tunnel, &ls->handle, &ls->ip_key, usercontrollerLocalTimeMS());

        if (result != kUserAdmissionOk)
        {
            usercontrollerLogAdmissionRejected(t, l, ls, result);

            // The upstream side was never opened, so we only finish the prev/downstream side that
            // initiated us. This is the natural "upstream is unavailable" close (close prev only).
            usercontrollerLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }

        ls->managed = true;
        if (UNLIKELY(! usercontrollerRegisterLine(t, l, ls)))
        {
            LOGW("UserController: rejected new connection: failed to register live enforcement state");
            authenticationclientUserReleaseConnection(ts->auth_client_tunnel, &ls->handle, &ls->ip_key);
            ls->managed = false;
            usercontrollerLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
    }

    tunnelNextUpStreamInit(t, l);
}
