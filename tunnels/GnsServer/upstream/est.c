#include "GnsServer/structure.h"

void gnsserverTunnelUpStreamEst(tunnel_t *t, line_t *line)
{
    gnsEndpointCarrierEst(t, line);
}
