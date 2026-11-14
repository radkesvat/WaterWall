#include "GnsServer/structure.h"

void gnsserverTunnelDownStreamPause(tunnel_t *t, line_t *line)
{
    gnsEndpointSetApplicationPaused(t, line, true);
}
