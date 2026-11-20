#include "GnsClient/structure.h"

void gnsclientTunnelUpStreamPause(tunnel_t *t, line_t *line)
{
    gnsEndpointSetApplicationPaused(t, line, true);
}
