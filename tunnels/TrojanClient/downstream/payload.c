#include "structure.h"

void trojanclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosed || ls->kind == kTrojanClientLineKindUdpApplication))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->kind == kTrojanClientLineKindDirect)
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
    size_t limit = kTrojanClientMaxUdpBufferedBytes;
    if (UNLIKELY(length > limit - ls->receive_bytes || ! bufferqueueTryPushBack(&ls->pending_down, &buf)))
    {
        lineReuseBuffer(l, buf);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return;
    }
    ls->receive_bytes += length;
    if (ls->receiving)
        return;
    line_t *application = ls->kind == kTrojanClientLineKindUdpCarrier ? ls->application_line : l;
    lineRef(l);
    if (application != l)
        lineRef(application);
    ls->receiving = true;
    /* A nested call publishes its separately bounded FIFO entry before returning.
     * All admitted batches complete here; Pause never converts ready frames into
     * an independent output backlog. Only an incomplete suffix survives return. */
    while (trojanclientAssociationAlive(t, l, application))
    {

        int header = trojanclientReadUdpHeader(ls);
        if (UNLIKELY(header < 0))
        {
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
            break;
        }
        if (header == 0 || ls->receive_bytes - ls->header_filled < ls->body_length)
            break;
        sbuf_t *body = trojanclientExtractUdpBody(ls);
        /* Parser cursor and accounting are committed before any reentrant callback. */
        tunnelPrevDownStreamPayload(t, application, body);
    }
    if (trojanclientAssociationAlive(t, l, application))
        ls->receiving = false;
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}
