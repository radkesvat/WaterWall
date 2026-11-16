#include "EnetServer/structure.h"

void enetserverTunnelUpStreamPause(tunnel_t *t, line_t *line)
{
    enetEndpointSetCarrierPaused(t, line, true);
}
