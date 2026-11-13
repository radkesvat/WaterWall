#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelUpStreamPause(tunnel_t *t, line_t *line)
{
    connectionstripeSetTransportPaused(t, line, true);
}
