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
    vmessclient_tstate_t *ts = tunnelGetState(t);
    atomicAddU64Explicit(&ts->stats.rx_wire_bytes, sbufGetLength(buf), memory_order_relaxed);
    assert(! sbufIsSplice(buf));
    buf = vmessclientCompactInput(l, buf);
    if (! ls->request_sent || ! bufferqueueTryPushBack(&ls->pending_down, &buf))
    {
        lineReuseBuffer(l, buf);
        vmessclientSetReason(ls, kVmessClientReasonRetainedInput);
        vmessclientCloseLine(t, l, kVmessClientCloseInternal);
        return;
    }
    vmessclientReceive(t, l);
}
