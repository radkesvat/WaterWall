#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    junkdatagramsender_lstate_t *ls = lineGetState(l, t);
    if (! junkdatagramsenderCanPublish(ls, kJunkDatagramSenderDirectionDownstream))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    tunnelPrevDownStreamPayload(t, l, buf);
}
