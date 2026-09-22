#include "structure.h"

void bgp4serverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    bgpPermission(t, l, lineGetState(l, t), false, true);
}
