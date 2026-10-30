#include "internal.h"

/* Cached metadata remains charged until its complete header is consumed.
 * Only an owned popped head can change; queued entries stay immutable. */
bool vlessserverGatherHeader(vlessserver_lstate_t *ls, uint16_t needed)
{
    assert(needed <= sizeof(ls->header));
    return bufferRangeGatherPrefix(
        lineGetBufferPool(ls->line), &ls->input_head, &ls->pending_up, ls->header, &ls->header_filled, needed);
}

void vlessserverRetainActiveHead(vlessserver_lstate_t *ls)
{
    /* Initial parsing only consumes this admitted head; no callback or new
     * admission intervenes before restoring it to the still-unbound queue. */
    bufferRangeRestoreHead(&ls->input_head, &ls->pending_up);
}

sbuf_t *vlessserverExtractUdpBody(vlessserver_lstate_t *ls, uint16_t bytes)
{
    sbuf_t *result = bufferRangeTakeExact(lineGetBufferPool(ls->line), &ls->input_head, &ls->pending_up, bytes);
    ls->input_bytes -= 2U + bytes;
    ls->header_filled = 0;
    return result;
}

bool vlessserverDrainInput(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, bool reject_short_uuid)
{
    if (ls->phase == kVlessServerPhaseWaitInitial)
    {
        if (! vlessserverHandleInitialRequest(t, l, ls, reject_short_uuid))
            return false;
    }

    if (ls->phase == kVlessServerPhaseUdpConnecting || ls->phase == kVlessServerPhaseUdpEstablished)
    {
        return vlessserverDrainUdpPackets(t, l, ls);
    }

    return true;
}
