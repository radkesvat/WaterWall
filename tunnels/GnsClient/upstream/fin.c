#include "GnsClient/structure.h"

void gnsclientTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    gnsEndpointApplicationFinish(t, line);
}
