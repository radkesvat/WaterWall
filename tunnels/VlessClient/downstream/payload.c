#include "internal.h"
#include "loggers/network_logger.h"

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
    /* Nested TCP output retains allocation capacity until its ordered handoff. */
    const size_t retained_charge = bufferreaderCharge(&ls->reader);
    const bool   charge_full     = ls->kind == kVlessClientLineKindDirect && ls->response_complete &&
                             (retained_charge > kVlessClientMaxOrderCharge ||
                              sbufGetQueueCharge(buf) > kVlessClientMaxOrderCharge - retained_charge);
    if (UNLIKELY(charge_full || ! bufferreaderTryPush(&ls->reader, &buf, limit)))
    {
        const size_t retained_bytes = bufferreaderLength(&ls->reader);
        const size_t incoming_bytes = sbufGetLength(buf);
        if (charge_full)
            LOGW("VlessClient: closing connection: receive input admission refused: storage charge limit exceeded "
                 "(retained_charge_bytes=%zu, incoming_charge_bytes=%zu, charge_limit_bytes=%u, "
                 "retained_bytes=%zu, incoming_bytes=%zu)",
                 retained_charge,
                 sbufGetQueueCharge(buf),
                 (unsigned) kVlessClientMaxOrderCharge,
                 retained_bytes,
                 incoming_bytes);
        else
            LOGW("VlessClient: closing connection: receive input admission refused: %s "
                 "(retained_bytes=%zu, incoming_bytes=%zu, byte_limit=%zu, retained_charge_bytes=%zu, "
                 "incoming_charge_bytes=%zu)",
                 retained_bytes > limit || incoming_bytes > limit - retained_bytes ? "byte limit exceeded"
                                                                                   : "queue admission failed",
                 retained_bytes,
                 incoming_bytes,
                 limit,
                 retained_charge,
                 sbufGetQueueCharge(buf));
        lineReuseBuffer(l, buf);
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        return;
    }
    if (ls->receiving)
    {
        /* UDP input must settle while the outer callback owns the parser. */
        if (ls->kind == kVlessClientLineKindUdpCarrier && ! bufferreaderSettle(&ls->reader, kVlessClientMaxInputCharge))
        {
            LOGW("VlessClient: closing connection: retained input charge limit exceeded "
                 "(retained_charge_bytes=%zu, limit_charge_bytes=%u)",
                 bufferreaderCharge(&ls->reader),
                 (unsigned) kVlessClientMaxInputCharge);
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        }
        return;
    }
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
        if (! vlessclientReadUdpHeader(ls) || ! bufferreaderBodyReady(&ls->reader, ls->body_length))
            break;
        sbuf_t *body = vlessclientExtractUdpBody(ls);
        /* Parser cursor and accounting are committed before any reentrant callback. */
        tunnelPrevDownStreamPayload(t, application, body);
    }
    if (vlessclientAssociationAlive(t, l, application))
    {
        /* Complete frames drain first, including after response metadata. */
        if (ls->kind == kVlessClientLineKindUdpCarrier && ! bufferreaderSettle(&ls->reader, kVlessClientMaxInputCharge))
        {
            LOGW("VlessClient: closing connection: retained input charge limit exceeded "
                 "(retained_charge_bytes=%zu, limit_charge_bytes=%u)",
                 bufferreaderCharge(&ls->reader),
                 (unsigned) kVlessClientMaxInputCharge);
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        }
        else
        {
            ls->receiving = false;
            vlessclientTryBypass(t, l, ls);
        }
    }
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}
