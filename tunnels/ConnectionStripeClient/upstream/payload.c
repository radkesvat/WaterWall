#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    connectionstripeApplicationPayload(t, line, buf);
}
