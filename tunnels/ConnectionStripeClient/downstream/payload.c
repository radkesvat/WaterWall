#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    connectionstripeTransportPayload(t, line, buf);
}
