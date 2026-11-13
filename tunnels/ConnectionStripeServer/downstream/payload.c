#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    connectionstripeApplicationPayload(t, line, buf);
}
