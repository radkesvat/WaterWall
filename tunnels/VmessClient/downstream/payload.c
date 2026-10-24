#include "internal.h"

void vmessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->kind == kVmessClientLineKindUdpApplication ||
        sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    assert(! sbufIsSplice(buf));
    buf = vmessclientCompactInput(l, buf);
    if (! ls->request_sent || ! bufferqueueTryPushBack(&ls->pending_down, &buf))
    {
        lineReuseBuffer(l, buf);
        vmessclientCloseLine(t, l, kVmessClientCloseInternal);
        return;
    }
    vmessclientReceive(t, l);
}
