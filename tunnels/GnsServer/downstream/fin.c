#include "GnsServer/structure.h"

void gnsserverTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    gnsEndpointApplicationFinish(t, line);
}
