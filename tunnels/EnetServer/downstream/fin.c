#include "EnetServer/structure.h"

void enetserverTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    enetEndpointApplicationFinish(t, line);
}
