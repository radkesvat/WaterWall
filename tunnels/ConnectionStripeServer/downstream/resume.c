#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelDownStreamResume(tunnel_t *t, line_t *line)
{
    connectionstripeSetApplicationPaused(t, line, false);
}
