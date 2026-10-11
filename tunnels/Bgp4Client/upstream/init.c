#include "structure.h"

void bgp4clientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);
    bgp4clientLinestateInitialize(ls, l);
    tunnelNextUpStreamInit(t, l);
}
