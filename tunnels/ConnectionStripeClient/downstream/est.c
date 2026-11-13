#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelDownStreamEst(tunnel_t *t, line_t *line)
{
    connectionstripeClientTransportEstablished(t, line);
}
