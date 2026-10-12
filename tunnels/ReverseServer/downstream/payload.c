#include "structure.h"

void reverseserverTunnelDownStreamPayload(tunnel_t *t, line_t *u, sbuf_t *buf)
{
    reverseserver_lstate_t *uls = lineGetState(u, t);
    if (uls->paired)
    {
        if (! reverseserverQueuePairedPayload(t, u, buf))
            tunnelPrevDownStreamPayload(t, uls->d, buf);
        return;
    }
    if (! reverseserverRetainPayload(t, u, buf))
        return;
    reverseserver_tstate_t     *ts  = tunnelGetState(t);
    reverseserver_thread_box_t *box = &ts->threadlocal_pool[lineGetWID(u)];
    if (atomicLoad(&box->d_count) != 0)
        reverseserverPair(t, u, box->d_root->d);
}
