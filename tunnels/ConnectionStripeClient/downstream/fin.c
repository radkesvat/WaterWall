#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    connectionstripeTransportFinish(t, line);
}
