#include "EnetClient/structure.h"

void enetclientTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    enetEndpointCarrierFinish(t, line);
}
