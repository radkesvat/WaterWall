#include "GnsClient/structure.h"

void gnsclientTunnelUpStreamResume(tunnel_t *t, line_t *line)
{
    gnsEndpointSetApplicationPaused(t, line, false);
}
