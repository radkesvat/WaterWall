#include "EnetClient/structure.h"

void enetclientTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    enetEndpointApplicationPayload(t, line, buf);
}
