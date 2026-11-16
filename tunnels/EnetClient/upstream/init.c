#include "EnetClient/structure.h"

void enetclientTunnelUpStreamInit(tunnel_t *t, line_t *line)
{
    enetEndpointClientInit(t, line);
}
