#include "EnetClient/structure.h"

void enetclientTunnelDownStreamPause(tunnel_t *t, line_t *line)
{
    enetEndpointSetCarrierPaused(t, line, true);
}
