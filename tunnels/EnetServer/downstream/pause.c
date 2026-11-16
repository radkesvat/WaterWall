#include "EnetServer/structure.h"

void enetserverTunnelDownStreamPause(tunnel_t *t, line_t *line)
{
    enetEndpointSetApplicationPaused(t, line, true);
}
