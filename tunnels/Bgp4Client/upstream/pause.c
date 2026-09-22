#include "structure.h"

void bgp4clientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    bgpPermission(t, l, lineGetState(l, t), false, true);
}
