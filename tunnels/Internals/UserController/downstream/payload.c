#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);

    if (ls->managed)
    {
        // Downstream payload counts as download for a forward-started line, upload for a reverse one.
        uint64_t bytes = (uint64_t) sbufGetLength(buf);
        if (usercontrollerAccountDirectional(t, ls, bytes, /*upstream_payload=*/false))
        {
            usercontrollerLogActiveClose(t, l, ls, "disabled, expired, traffic quota reached, or user removed");
            lineReuseBuffer(l, buf);
            usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
            return;
        }
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
