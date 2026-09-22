#include "structure.h"

void bgp4clientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    bgpPermission(t, l, lineGetState(l, t), false, false);
}
