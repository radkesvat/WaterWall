#include "GnsServer/structure.h"

void gnsserverTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    gnsEndpointCarrierFinish(t, line);
}
