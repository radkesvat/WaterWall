#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    connectionstripeApplicationFinish(t, line);
}
