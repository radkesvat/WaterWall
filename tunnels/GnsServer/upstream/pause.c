#include "GnsServer/structure.h"

void gnsserverTunnelUpStreamPause(tunnel_t *t, line_t *line)
{
    gnsEndpointSetCarrierPaused(t, line, true);
}
