#include "EnetServer/structure.h"

void enetserverTunnelDownStreamResume(tunnel_t *t, line_t *line)
{
    enetEndpointSetApplicationPaused(t, line, false);
}
