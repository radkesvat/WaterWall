#include "GnsClient/structure.h"

void gnsclientTunnelDownStreamPause(tunnel_t *t, line_t *line)
{
    gnsEndpointSetCarrierPaused(t, line, true);
}
