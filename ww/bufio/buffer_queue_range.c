#include "buffer_queue_range.h"
#include "splice_buffer.h"

static sbuf_t *rangeHead(sbuf_t **active_head, buffer_queue_t *tail)
{
    if (*active_head == NULL)
        *active_head = bufferqueuePopFront(tail);
    return *active_head;
}

sbuf_t *bufferRangeTakeExact(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, uint32_t bytes)
{
    assert(pool != NULL && active_head != NULL && tail != NULL);
    assert(tail->budget == NULL);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
#ifndef NDEBUG
    const uint32_t    active_bytes = *active_head == NULL ? 0 : sbufGetLength(*active_head);
    buffer_pool_fit_t fit;
    assert(bytes <= active_bytes || bytes - active_bytes <= bufferqueueGetBufLen(tail));
    assert(bufferpoolQueryBestFit(pool, bytes, padding, &fit));
#endif
    if (bytes == 0)
        return bufferpoolGetBestFit(pool, 0, padding);

    sbuf_t *head = rangeHead(active_head, tail);
    assert(head != NULL);
    if (sbufGetLength(head) == bytes && sbufGetLeftCapacity(head) >= padding)
    {
        *active_head = NULL;
        return head;
    }

    bool     has_pipe  = sbufIsSplice(head);
    uint32_t remaining = bytes - min(bytes, sbufGetLength(head));
    c_foreach(i, ww_sbuffer_queue_t, tail->q)
    {
        if (remaining == 0)
            break;
        has_pipe |= sbufIsSplice(*i.ref);
        remaining -= min(remaining, sbufGetLength(*i.ref));
    }

    sbuf_t *result = has_pipe ? bufferpoolGetSpliceBuffer(pool) : NULL;
    if (result != NULL && sbufGetLeftCapacity(result) < padding)
    {
        bufferpoolReuseBuffer(pool, result);
        result = NULL;
    }
    if (result == NULL)
        result = bufferpoolGetBestFit(pool, bytes, padding);

    remaining = bytes;
    while (remaining != 0)
    {
        head = rangeHead(active_head, tail);
        assert(head != NULL);
        const uint32_t count = min(remaining, sbufGetLength(head));
        result               = sbufMoveRangeTo(pool, head, result, count, bytes, padding);
        remaining -= count;
        if (sbufGetLength(head) == 0)
        {
            bufferpoolReuseBuffer(pool, head);
            *active_head = NULL;
        }
    }
    return result;
}
