#include "structure.h"

void bgp4serverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    bgp4server_lstate_t *ls = lineGetState(l, t);
    if (! bgp4serverLinestateInitialize(ls, l))
    {
        LOGE("Bgp4Server: could not allocate receive stream");
        bgp4serverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    tunnelNextUpStreamInit(t, l);
}
