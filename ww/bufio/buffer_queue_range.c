#include "buffer_queue_range.h"
#include "splice_buffer.h"

static sbuf_t *rangeHead(sbuf_t **active_head, buffer_queue_t *tail)
{
    if (*active_head == NULL)
        *active_head = bufferqueuePopFront(tail);
    return *active_head;
}

bool bufferRangeGatherPrefix(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, uint8_t *dst,
                             uint16_t *filled, uint16_t needed)
{
    assert(pool != NULL && active_head != NULL && tail != NULL && dst != NULL && filled != NULL);
    assert(tail->budget == NULL);
    while (*filled < needed)
    {
        sbuf_t *head = rangeHead(active_head, tail);
        if (head == NULL)
            return false;
        const uint32_t count = min(needed - *filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, dst + *filled, count);
        *filled += count;
        if (sbufGetLength(head) == 0)
        {
            bufferpoolReuseBuffer(pool, head);
            *active_head = NULL;
        }
    }
    return true;
}

void bufferRangeRestoreHead(sbuf_t **active_head, buffer_queue_t *tail)
{
    assert(active_head != NULL && tail != NULL);
    assert(tail->budget == NULL);
    if (*active_head != NULL)
    {
        bufferqueuePushFront(tail, *active_head);
        *active_head = NULL;
    }
}

bool bufferRangeSettleRetained(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, size_t max_charge,
                               size_t max_entries)
{
    assert(pool != NULL && active_head != NULL && tail != NULL && max_entries != 0);
    assert(tail->budget == NULL);
    sbuf_t      *head        = *active_head;
    const size_t head_charge = head == NULL ? 0 : sbufGetQueueCharge(head);
    if (head_charge <= max_charge && bufferqueueGetCharge(tail) <= max_charge - head_charge &&
        bufferqueueGetBufCount(tail) <= max_entries - (head != NULL))
        return true;

    const uint32_t head_bytes = head == NULL ? 0 : sbufGetLength(head);
    if (bufferqueueGetBufLen(tail) > UINT32_MAX - head_bytes)
        return false;
    const uint32_t bytes = (uint32_t) bufferqueueGetBufLen(tail) + head_bytes;
    if (bytes == 0)
    {
        while ((head = rangeHead(active_head, tail)) != NULL)
        {
            bufferpoolReuseBuffer(pool, head);
            *active_head = NULL;
        }
        return true;
    }
    const uint16_t    padding = bufferpoolGetLargeBufferPadding(pool);
    buffer_pool_fit_t fit;
    if (! bufferpoolQueryBestFit(pool, bytes, padding, &fit) || fit.allocation_charge > max_charge)
        return false;

    uint32_t capacity = bytes;
    if (head != NULL)
    {
        /* Growth headroom is optional; the exact retained bytes must fit first. */
        const uint64_t grown = max(bytes, (uint64_t) sbufGetLength(head) * 2U);
        if (bufferpoolQueryBestFit(pool, grown, padding, &fit) && fit.allocation_charge <= max_charge)
            capacity = (uint32_t) grown;
    }

    sbuf_t *combined = NULL;
    if (head != NULL && head_charge <= max_charge && sbufGetLeftCapacity(head) >= padding &&
        (sbufIsSplice(head) ? head->curpos == head->l_pad : bufferqueueGetBufLen(tail) <= sbufGetTailCapacity(head)))
    {
        combined     = head;
        *active_head = NULL;
    }
    else
    {
        bool has_pipe = head != NULL && sbufIsSplice(head);
        c_foreach(entry, ww_sbuffer_queue_t, tail->q) has_pipe |= sbufIsSplice(*entry.ref);
        combined = has_pipe ? bufferpoolGetSpliceBuffer(pool) : NULL;
        if (combined != NULL && sbufGetLeftCapacity(combined) < padding)
        {
            bufferpoolReuseBuffer(pool, combined);
            combined = NULL;
        }
        if (combined == NULL)
            combined = bufferpoolGetBestFit(pool, capacity, padding);
    }
    if (sbufIsSplice(combined))
    {
        size_t         charge;
        const uint64_t pipe_capacity = (uint64_t) bytes + sbufGetLeftPadding(combined);
        if (pipe_capacity > UINT32_MAX || ! sbufTryComputeQueueCharge((uint32_t) pipe_capacity, &charge) ||
            charge > max_charge)
        {
            if (combined == head)
                *active_head = combined;
            else
                bufferpoolReuseBuffer(pool, combined);
            combined = bufferpoolGetBestFit(pool, capacity, padding);
        }
    }
    while ((head = rangeHead(active_head, tail)) != NULL)
    {
        combined = sbufMoveRangeTo(pool, head, combined, sbufGetLength(head), capacity, padding);
        bufferpoolReuseBuffer(pool, head);
        *active_head = NULL;
    }
    *active_head = combined;
    assert(sbufGetLength(combined) == bytes && sbufGetQueueCharge(combined) <= max_charge);
    return true;
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
