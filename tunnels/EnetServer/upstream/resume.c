#include "EnetServer/structure.h"

void enetserverTunnelUpStreamResume(tunnel_t *t, line_t *line)
{
    enetEndpointSetCarrierPaused(t, line, false);
}
