#include "GnsServer/structure.h"

void gnsserverTunnelUpStreamResume(tunnel_t *t, line_t *line)
{
    gnsEndpointSetCarrierPaused(t, line, false);
}
