#include "structure.h"

void reverseserverTunnelDownStreamFinish(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *uls = lineGetState(u, t);
    if (uls->paired)
    {
        line_t *d = uls->d;
        reverseserverLinestateDestroy(uls);
        reverseserverLinestateDestroy(lineGetState(d, t));
        tunnelPrevDownStreamFinish(t, d);
        return;
    }
    if (uls->handshaked)
    {
        reverseserver_tstate_t *ts = tunnelGetState(t);
        reverseserverRemoveConnectionU(&ts->threadlocal_pool[lineGetWID(u)], uls);
    }
    reverseserverLinestateDestroy(uls);
}
