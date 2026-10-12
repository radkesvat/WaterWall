#include "structure.h"

void reverseserverTunnelUpStreamFinish(tunnel_t *t, line_t *d)
{
    reverseserver_lstate_t *dls = lineGetState(d, t);
    if (dls->paired)
    {
        line_t *u = dls->u;
        reverseserverLinestateDestroy(dls);
        reverseserverLinestateDestroy(lineGetState(u, t));
        tunnelNextUpStreamFinish(t, u);
        return;
    }
    if (dls->handshaked)
    {
        reverseserver_tstate_t *ts = tunnelGetState(t);
        reverseserverRemoveConnectionD(&ts->threadlocal_pool[lineGetWID(d)], dls);
    }
    reverseserverLinestateDestroy(dls);
}
