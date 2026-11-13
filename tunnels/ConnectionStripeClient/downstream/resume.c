#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelDownStreamResume(tunnel_t *t, line_t *line)
{
    connectionstripeSetTransportPaused(t, line, false);
}
