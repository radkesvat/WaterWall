#include "EnetServer/structure.h"

void enetserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    enetEndpointApplicationPayload(t, line, buf);
}
