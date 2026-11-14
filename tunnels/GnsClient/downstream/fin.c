#include "GnsClient/structure.h"

void gnsclientTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    gnsEndpointCarrierFinish(t, line);
}
