#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    connectionstripeTransportFinish(t, line);
}
