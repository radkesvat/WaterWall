#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelDownStreamPause(tunnel_t *t, line_t *line)
{
    connectionstripeSetApplicationPaused(t, line, true);
}
