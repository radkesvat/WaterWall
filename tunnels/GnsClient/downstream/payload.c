#include "GnsClient/structure.h"

void gnsclientTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    gnsEndpointCarrierPayload(t, line, buf);
}
