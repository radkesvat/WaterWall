#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);

    if (ls->managed)
    {
        // Reverse Init flips the user's upload/download mapping, not callback direction.
        uint64_t bytes = (uint64_t) sbufGetLength(buf);
        if (usercontrollerObserveDirectional(t, ls, bytes, /*upstream_payload=*/false))
        {
            usercontrollerLogActiveClose(t, l, ls, "disabled, expired, traffic quota reached, or user removed");
            lineReuseBuffer(l, buf);
            usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
            return;
        }
        usercontrollerBandwidthSubmit(t, l, buf, false);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
