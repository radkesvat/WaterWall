#include "structure.h"

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

bool vlessserverRetainActiveHead(vlessserver_lstate_t *ls)
{
    if (ls->input_head != NULL)
    {
        if (! bufferqueueTryPushFront(&ls->pending_up, &ls->input_head))
            return false;
        ls->input_head = NULL;
    }
    return true;
}

sbuf_t *vlessserverExtractUdpBody(vlessserver_lstate_t *ls, uint16_t bytes)
{
    buffer_pool_t *pool    = lineGetBufferPool(ls->line);
    uint16_t       padding = bufferpoolGetLargeBufferPadding(pool);
    sbuf_t        *head    = receiveHead(ls);
    sbuf_t        *result  = NULL;
    assert(bytes != 0 && head != NULL);
    if (sbufGetLength(head) == bytes && sbufGetLeftCapacity(head) >= padding)
    {
        result         = head;
        ls->input_head = NULL;
    }
    else
    {
        bool   has_pipe = sbufIsSplice(head);
        size_t range    = sbufGetLength(head);
        c_foreach(i, ww_sbuffer_queue_t, ls->pending_up.q)
        {
            if (range >= bytes)
                break;
            has_pipe |= sbufIsSplice(*i.ref);
            range += sbufGetLength(*i.ref);
        }
        if (has_pipe)
            result = bufferpoolGetSpliceBuffer(pool);
        if (result != NULL && sbufGetLeftCapacity(result) < padding)
        {
            bufferpoolReuseBuffer(pool, result);
            result = NULL;
        }
        if (result == NULL)
            result = bufferpoolGetBestFit(pool, bytes, padding);
        uint32_t remaining = bytes;
        while (remaining != 0)
        {
            head           = receiveHead(ls);
            uint32_t count = min(remaining, sbufGetLength(head));
            result         = sbufMoveRangeTo(pool, head, result, count, bytes, padding);
            remaining -= count;
            recycleEmptyHead(ls);
        }
    }
    ls->input_bytes -= 2U + bytes;
    ls->header_filled = 0;
    return result;
}
