#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (! bgp4serverWrapPayload(t, l, &buf, bgp4serverNextPayloadType()))
    {
        bgp4serverCloseLine(t, l);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
