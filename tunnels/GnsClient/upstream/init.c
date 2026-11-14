#include "GnsClient/structure.h"

void gnsclientTunnelUpStreamInit(tunnel_t *t, line_t *line)
{
    gnsEndpointClientInit(t, line);
}
