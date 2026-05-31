#include "structure.h"

void sniffrouterTunnelDestroy(tunnel_t *t)
{
    sniffrouterRouteTableDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
