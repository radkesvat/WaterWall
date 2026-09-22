#include "structure.h"

void bgp4clientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);
    if (! bgp4clientLinestateInitialize(ls, l))
    {
        LOGE("Bgp4Client: could not allocate receive stream");
        bgp4clientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    tunnelNextUpStreamInit(t, l);
}
