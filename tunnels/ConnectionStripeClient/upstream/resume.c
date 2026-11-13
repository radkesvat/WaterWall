#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelUpStreamResume(tunnel_t *t, line_t *line)
{
    connectionstripeSetApplicationPaused(t, line, false);
}
