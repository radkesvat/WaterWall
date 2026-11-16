#include "EnetServer/structure.h"

void enetserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    enetEndpointCarrierPayload(t, line, buf);
}
