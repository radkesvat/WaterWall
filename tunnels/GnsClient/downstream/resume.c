#include "GnsClient/structure.h"

void gnsclientTunnelDownStreamResume(tunnel_t *t, line_t *line)
{
    gnsEndpointSetCarrierPaused(t, line, false);
}
