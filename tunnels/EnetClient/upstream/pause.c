#include "EnetClient/structure.h"

void enetclientTunnelUpStreamPause(tunnel_t *t, line_t *line)
{
    enetEndpointSetApplicationPaused(t, line, true);
}
