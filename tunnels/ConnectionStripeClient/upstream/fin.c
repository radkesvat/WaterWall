#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    connectionstripeApplicationFinish(t, line);
}
