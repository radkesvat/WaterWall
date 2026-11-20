#include "GnsServer/structure.h"

void gnsserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    gnsEndpointApplicationPayload(t, line, buf);
}
