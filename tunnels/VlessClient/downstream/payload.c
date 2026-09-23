#include "structure.h"

void vlessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kVlessClientPhaseClosed || ls->kind == kVlessClientLineKindUdpApplication))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->kind == kVlessClientLineKindDirect && ls->response_complete && ! ls->receiving)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    uint32_t length = sbufGetLength(buf);
    if (UNLIKELY(length == 0))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    size_t limit = ls->kind == kVlessClientLineKindDirect
                       ? (ls->response_complete ? kVlessClientMaxOrderBytes : kVlessClientMaxTcpWireBytes)
                       : kVlessClientMaxUdpBufferedBytes;
    if (UNLIKELY(length > limit - ls->receive_bytes || ! bufferqueueTryPushBack(&ls->pending_down, &buf)))
    {
        lineReuseBuffer(l, buf);
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        return;
    }
    ls->receive_bytes += length;
    if (ls->receiving)
        return;
    line_t *application = ls->kind == kVlessClientLineKindUdpCarrier ? ls->application_line : l;
    lineRef(l);
    if (application != l)
        lineRef(application);
    ls->receiving = true;
    /* A nested call publishes its separately bounded FIFO entry before returning.
     * All admitted batches complete here; Pause never converts ready frames into
     * an independent output backlog. Only an incomplete suffix survives return. */
    while (vlessclientAssociationAlive(t, l, application))
    {
        if (! ls->response_complete)
        {
            int response = vlessclientReadResponse(ls);
            if (UNLIKELY(response < 0))
            {
                vlessclientCloseLine(t, l, kVlessClientCloseInternal);
                break;
            }
            if (response == 0)
                break;
        }
        if (ls->kind == kVlessClientLineKindDirect)
        {
            sbuf_t *body = vlessclientTakeTcpBody(ls);
            if (body == NULL)
                break;
            tunnelPrevDownStreamPayload(t, application, body);
            continue;
        }
        int header = vlessclientReadUdpHeader(ls);
        if (UNLIKELY(header < 0))
        {
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
            break;
        }
        if (header == 0 || ls->receive_bytes - ls->header_filled < ls->body_length)
            break;
        sbuf_t *body = vlessclientExtractUdpBody(ls);
        /* Parser cursor and accounting are committed before any reentrant callback. */
        tunnelPrevDownStreamPayload(t, application, body);
    }
    if (vlessclientAssociationAlive(t, l, application))
        ls->receiving = false;
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}
