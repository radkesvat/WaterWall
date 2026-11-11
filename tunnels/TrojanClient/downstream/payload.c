#include "internal.h"
#include "loggers/network_logger.h"

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
    if (UNLIKELY(! bufferreaderTryPush(&ls->reader, &buf, kTrojanClientMaxUdpBufferedBytes)))
    {
        LOGW("TrojanClient: closing connection: receive input admission refused "
             "(retained_bytes=%zu, incoming_bytes=%zu, byte_limit=%zu, retained_charge_bytes=%zu, "
             "incoming_charge_bytes=%zu)",
             bufferreaderLength(&ls->reader),
             sbufGetLength(buf),
             (size_t) kTrojanClientMaxUdpBufferedBytes,
             bufferreaderCharge(&ls->reader),
             sbufGetQueueCharge(buf));
        lineReuseBuffer(l, buf);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return;
    }
    if (ls->receiving)
    {
        /* Nested input must settle while the outer callback owns the parser. */
        if (! bufferreaderSettle(&ls->reader, kTrojanClientMaxInputCharge))
        {
            LOGW("TrojanClient: closing connection: retained input charge limit exceeded "
                 "(retained_charge_bytes=%zu, limit_charge_bytes=%u)",
                 bufferreaderCharge(&ls->reader),
                 (unsigned) kTrojanClientMaxInputCharge);
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        }
        return;
    }
    assert(ls->kind == kTrojanClientLineKindUdpCarrier);
    line_t *application = ls->application_line;
    lineRef(l);
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
        if (header == 0 || ! bufferreaderBodyReady(&ls->reader, ls->body_length))
            break;
        sbuf_t *body = trojanclientExtractUdpBody(ls);
        /* Parser cursor and accounting are committed before any reentrant callback. */
        tunnelPrevDownStreamPayload(t, application, body);
    }
    if (trojanclientAssociationAlive(t, l, application))
    {
        /* Complete frames drain first; only incomplete input survives return. */
        if (! bufferreaderSettle(&ls->reader, kTrojanClientMaxInputCharge))
        {
            LOGW("TrojanClient: closing connection: retained input charge limit exceeded "
                 "(retained_charge_bytes=%zu, limit_charge_bytes=%u)",
                 bufferreaderCharge(&ls->reader),
                 (unsigned) kTrojanClientMaxInputCharge);
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        }
        else
            ls->receiving = false;
    }
    lineUnref(application);
    lineUnref(l);
}
