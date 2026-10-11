#include "structure.h"

void bgp4serverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    bgp4server_lstate_t *ls = lineGetState(l, t);
    bgp4serverLinestateInitialize(ls, l);
    tunnelNextUpStreamInit(t, l);
}
