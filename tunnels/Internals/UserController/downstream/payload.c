#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);
    usercontroller_lstate_t *ls = lineGetState(l, t);

    if (ls->managed)
    {
        // Downstream payload is remote -> client, i.e. the user's download.
        uint64_t bytes = (uint64_t) sbufGetLength(buf);
        bool     close = authenticationclientUserAccountTraffic(ts->auth_client_tunnel, &ls->handle, 0, bytes,
                                                                usercontrollerLocalTimeMS());
        if (close)
        {
            LOGW("UserController: closing active connection (disabled, expired, traffic quota reached, or user "
                 "removed)");
            lineReuseBuffer(l, buf);
            usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
            return;
        }
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
