#include "GnsServer/structure.h"

void gnsserverTunnelDownStreamResume(tunnel_t *t, line_t *line)
{
    gnsEndpointSetApplicationPaused(t, line, false);
}
