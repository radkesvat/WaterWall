#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);

    if (ls->managed)
    {
        // Upstream payload counts as upload for a forward-started line, download for a reverse one.
        uint64_t bytes = (uint64_t) sbufGetLength(buf);
        if (usercontrollerAccountDirectional(t, ls, bytes, /*upstream_payload=*/true))
        {
            usercontrollerLogActiveClose(t, l, ls, "disabled, expired, traffic quota reached, or user removed");
            lineReuseBuffer(l, buf);
            usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
            return;
        }
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
