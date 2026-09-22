#include "structure.h"

void bgp4serverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    bgpPermission(t, l, lineGetState(l, t), true, false);
}
