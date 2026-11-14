#include "GnsServer/structure.h"

void gnsserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    gnsEndpointCarrierPayload(t, line, buf);
}
