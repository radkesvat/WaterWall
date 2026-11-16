#include "EnetClient/structure.h"

void enetclientTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    enetEndpointCarrierPayload(t, line, buf);
}
