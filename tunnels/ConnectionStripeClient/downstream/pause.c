#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelDownStreamPause(tunnel_t *t, line_t *line)
{
    connectionstripeSetTransportPaused(t, line, true);
}
