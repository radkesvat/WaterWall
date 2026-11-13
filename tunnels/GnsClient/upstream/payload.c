#include "GnsClient/structure.h"

void gnsclientTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    gnsEndpointApplicationPayload(t, line, buf);
}
