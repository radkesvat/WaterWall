#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);

    if (ls->managed)
    {
        // Observe raw arrival before queueing; quota is charged only at handoff.
        uint64_t bytes = (uint64_t) sbufGetLength(buf);
        if (usercontrollerObserveDirectional(t, ls, bytes, /*upstream_payload=*/true))
        {
            usercontrollerLogActiveClose(t, l, ls, "disabled, expired, traffic quota reached, or user removed");
            lineReuseBuffer(l, buf);
            usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
            return;
        }
        usercontrollerBandwidthSubmit(t, l, buf, true);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
