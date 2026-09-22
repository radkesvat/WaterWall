#include "structure.h"

void bgp4clientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    bgpPermission(t, l, lineGetState(l, t), true, false);
}
