#include "EnetClient/structure.h"

void enetclientTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    enetEndpointApplicationFinish(t, line);
}
