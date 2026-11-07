#include "structure.h"

void kcpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    /* The incoming normal line belongs to the UDP source. Service admission waits for CONFIRM. */
    kcpserver_lstate_t *ls = lineGetState(l, t);
    if (! kcpserverLinestateInitialize(ls, l, t))
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}
