#include "EnetServer/structure.h"

void enetserverTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    enetEndpointCarrierFinish(t, line);
}
