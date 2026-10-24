#include "internal.h"

void vmessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vmessclient_lstate_t *ls     = lineGetState(l, t);
    size_t                length = sbufGetLength(buf);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->kind == kVmessClientLineKindUdpCarrier || ! length)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    line_t               *next    = ls->kind == kVmessClientLineKindUdpApplication ? ls->carrier_line : l;
    vmessclient_lstate_t *next_ls = lineGetState(next, t);
    if (ls->kind == kVmessClientLineKindUdpApplication)
    {
        /* Before bootstrap, use the same maximum-frame arithmetic as the codec. */
        vmessclient_tstate_t *ts       = tunnelGetState(t);
        vmess_body_ctx_t      geometry = {.security = ts->security, .options = ts->options};
        if (length > vmessBodyMaxPlaintext(next_ls->request_sent ? &next_ls->output_crypto : &geometry))
        {
            lineReuseBuffer(l, buf);
            return;
        }
    }
    assert(! sbufIsSplice(buf));
    buf = vmessclientCompactInput(l, buf);
    if (! bufferqueueTryPushBack(&next_ls->pending_up, &buf))
    {
        lineReuseBuffer(l, buf);
        vmessclientCloseLine(t, next, kVmessClientCloseInternal);
        return;
    }
    vmessclientTransmit(t, next);
}
