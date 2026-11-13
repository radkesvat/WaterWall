#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelUpStreamResume(tunnel_t *t, line_t *line)
{
    connectionstripeSetTransportPaused(t, line, false);
}
