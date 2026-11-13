#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    connectionstripeTransportPayload(t, line, buf);
}
