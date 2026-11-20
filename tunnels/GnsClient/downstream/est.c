#include "GnsClient/structure.h"

void gnsclientTunnelDownStreamEst(tunnel_t *t, line_t *line)
{
    gnsEndpointCarrierEst(t, line);
}
