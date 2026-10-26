#include "buffer_queue_range.h"
#include "internal.h"

static sbuf_t *receiveHead(vlessserver_lstate_t *ls)
{
    if (ls->input_head == NULL)
        ls->input_head = bufferqueuePopFront(&ls->pending_up);
    return ls->input_head;
}

static void recycleEmptyHead(vlessserver_lstate_t *ls)
{
    if (ls->input_head != NULL && sbufGetLength(ls->input_head) == 0)
    {
        lineReuseBuffer(ls->line, ls->input_head);
        ls->input_head = NULL;
    }
}

/* Cached metadata remains charged until its complete header is consumed.
 * Only an owned popped head can change; queued entries stay immutable. */
bool vlessserverGatherHeader(vlessserver_lstate_t *ls, uint16_t needed)
{
    assert(needed <= sizeof(ls->header));
    while (ls->header_filled < needed)
    {
        sbuf_t *head = receiveHead(ls);
        if (head == NULL)
            return false;
        uint32_t count = min(needed - ls->header_filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, ls->header + ls->header_filled, count);
        ls->header_filled += count;
        recycleEmptyHead(ls);
    }
    return true;
}

void vlessserverRetainActiveHead(vlessserver_lstate_t *ls)
{
    if (ls->input_head != NULL)
    {
        /* Initial parsing only consumes this admitted head; no callback or new
         * admission intervenes before restoring it to the still-unbound queue. */
        assert(ls->pending_up.budget == NULL);
        bufferqueuePushFront(&ls->pending_up, ls->input_head);
        ls->input_head = NULL;
    }
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
