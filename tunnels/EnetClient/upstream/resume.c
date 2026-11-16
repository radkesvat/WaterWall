#include "EnetClient/structure.h"

void enetclientTunnelUpStreamResume(tunnel_t *t, line_t *line)
{
    enetEndpointSetApplicationPaused(t, line, false);
}
