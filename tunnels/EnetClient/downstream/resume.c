#include "EnetClient/structure.h"

void enetclientTunnelDownStreamResume(tunnel_t *t, line_t *line)
{
    enetEndpointSetCarrierPaused(t, line, false);
}
