#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelUpStreamPause(tunnel_t *t, line_t *line)
{
    connectionstripeSetApplicationPaused(t, line, true);
}
