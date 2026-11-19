#include "structure.h"

void reverseserverTunnelDownStreamPayload(tunnel_t *t, line_t *u, sbuf_t *buf)
{
    reverseserver_lstate_t *uls = lineGetState(u, t);
    if (uls->phase == kReverseHalfPaired)
    {
        reverseserverForwardPairedPayload(t, u, buf);
        return;
    }
    if (uls->phase != kReverseHalfWaiting)
    {
        lineReuseBuffer(u, buf);
        return;
    }
    if (! reverseserverRetainPayload(t, u, buf))
        return;
    reverseserver_tstate_t     *ts  = tunnelGetState(t);
    reverseserver_thread_box_t *box = &ts->threadlocal_pool[lineGetWID(u)];
    if (box->reverse_links.head != NULL)
        reverseserverPair(t, u, box->reverse_links.head->d);
}
