#include "buffer_reader.h"
#include "splice_buffer.h"

static sbuf_t *readerHead(sbuf_t **active_head, buffer_queue_t *tail)
{
    if (*active_head == NULL)
        *active_head = bufferqueuePopFront(tail);
    return *active_head;
}

static bool readerGatherPrefix(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, uint8_t *dst,
                               uint16_t *filled, uint16_t needed)
{
    assert(pool != NULL && active_head != NULL && tail != NULL && dst != NULL && filled != NULL);
    assert(tail->budget == NULL);
    while (*filled < needed)
    {
        sbuf_t *head = readerHead(active_head, tail);
        if (head == NULL)
            return false;
        const uint16_t count = (uint16_t) MIN_SIZE(needed - *filled, sbufGetLength(head));
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

static bool readerSettleRetained(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, size_t max_charge)
{
    assert(pool != NULL && active_head != NULL && tail != NULL);
    assert(tail->budget == NULL);
    sbuf_t      *head        = *active_head;
    const size_t head_charge = head == NULL ? 0 : sbufGetQueueCharge(head);
    if (head_charge <= max_charge && bufferqueueGetCharge(tail) <= max_charge - head_charge)
        return true;

    const size_t head_bytes = head == NULL ? 0 : sbufGetLength(head);
    if (head_bytes > UINT32_MAX || bufferqueueGetBufLen(tail) > UINT32_MAX - head_bytes)
        return false;
    const uint32_t bytes = (uint32_t) (bufferqueueGetBufLen(tail) + head_bytes);
    if (bytes == 0)
    {
        while ((head = readerHead(active_head, tail)) != NULL)
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
        const uint64_t grown = MAX_U64(bytes, (uint64_t) sbufGetLength(head) * 2U);
        if (bufferpoolQueryBestFit(pool, grown, padding, &fit) && fit.allocation_charge <= max_charge)
            capacity = (uint32_t) grown;
    }

    sbuf_t *combined = NULL;
    if (head != NULL && head_charge <= max_charge && sbufGetLeftCapacity(head) >= padding &&
        (sbufIsSplice(head) ? sbufGetLeftCapacity(head) == head->l_pad
                            : bufferqueueGetBufLen(tail) <= sbufGetTailCapacity(head)))
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
    while ((head = readerHead(active_head, tail)) != NULL)
    {
        combined = sbufMoveRangeTo(pool, head, combined, sbufGetLength(head), capacity, padding);
        bufferpoolReuseBuffer(pool, head);
        *active_head = NULL;
    }
    *active_head = combined;
    assert(sbufGetLength(combined) == bytes && sbufGetQueueCharge(combined) <= max_charge);
    return true;
}

static sbuf_t *readerTakeExact(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, uint32_t bytes)
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

    sbuf_t *head = readerHead(active_head, tail);
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
        head = readerHead(active_head, tail);
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

void bufferreaderInit(buffer_reader_t *reader, buffer_pool_t *pool, uint8_t *header, uint16_t header_capacity)
{
    assert(pool != NULL && header != NULL && header_capacity != 0);
    *reader = (buffer_reader_t) {.pool = pool, .header = header, .header_capacity = header_capacity};
    bufferqueueInitEmpty(&reader->pending);
}

void bufferreaderClear(buffer_reader_t *reader)
{
    if (reader->head != NULL)
        bufferpoolReuseBuffer(reader->pool, reader->head);
    reader->head = NULL;
    bufferqueueDestroy(&reader->pending);
    reader->bytes         = 0;
    reader->header_filled = 0;
}

void bufferreaderDestroy(buffer_reader_t *reader)
{
    bufferreaderClear(reader);
    *reader = (buffer_reader_t) {0};
}

bool bufferreaderTryPush(buffer_reader_t *reader, sbuf_t **input, size_t max_bytes)
{
    const size_t bytes = sbufGetLength(*input);
    if (reader->bytes > max_bytes || bytes > max_bytes - reader->bytes ||
        ! bufferqueueTryPushBack(&reader->pending, input))
        return false;
    reader->bytes += bytes;
    return true;
}

bool bufferreaderGather(buffer_reader_t *reader, uint16_t needed)
{
    assert(needed <= reader->header_capacity);
    return readerGatherPrefix(
        reader->pool, &reader->head, &reader->pending, reader->header, &reader->header_filled, needed);
}

void bufferreaderConsumeHeader(buffer_reader_t *reader)
{
    assert(reader->bytes >= reader->header_filled);
    reader->bytes -= reader->header_filled;
    reader->header_filled = 0;
}

sbuf_t *bufferreaderTakeBody(buffer_reader_t *reader, uint32_t bytes)
{
    assert(bufferreaderBodyReady(reader, bytes));
    sbuf_t *body = readerTakeExact(reader->pool, &reader->head, &reader->pending, bytes);
    reader->bytes -= bytes;
    bufferreaderConsumeHeader(reader);
    return body;
}

sbuf_t *bufferreaderTakeChunk(buffer_reader_t *reader)
{
    assert(reader->header_filled == 0);
    sbuf_t *body = reader->head;
    if (body != NULL)
        reader->head = NULL;
    else
        body = bufferqueuePopFront(&reader->pending);
    if (body != NULL)
    {
        assert(reader->bytes >= sbufGetLength(body));
        reader->bytes -= sbufGetLength(body);
    }
    return body;
}

bool bufferreaderSettle(buffer_reader_t *reader, size_t max_charge)
{
    return readerSettleRetained(reader->pool, &reader->head, &reader->pending, max_charge);
}

bool bufferreaderMoveToQueue(buffer_reader_t *reader, buffer_queue_t *destination, bool restore_header)
{
    assert(destination != &reader->pending && destination->budget == NULL && bufferqueueGetBufCount(destination) == 0 &&
           reader->pending.budget == NULL);
    assert(restore_header || reader->header_filled == 0);
    if (reader->head != NULL)
    {
        if (! bufferqueueTryPushFront(&reader->pending, &reader->head))
            return false;
        reader->head = NULL;
    }
    if (restore_header && reader->header_filled != 0)
    {
        sbuf_t *prefix =
            bufferpoolGetBestFit(reader->pool, reader->header_filled, bufferpoolGetLargeBufferPadding(reader->pool));
        sbufWrite(prefix, reader->header, reader->header_filled);
        sbufSetLength(prefix, reader->header_filled);
        if (! bufferqueueTryPushFront(&reader->pending, &prefix))
        {
            bufferpoolReuseBuffer(reader->pool, prefix);
            return false;
        }
    }
    bufferqueueDestroy(destination);
    *destination = reader->pending;
    bufferqueueInitEmpty(&reader->pending);
    reader->bytes         = 0;
    reader->header_filled = 0;
    return true;
}

size_t bufferreaderCharge(const buffer_reader_t *reader)
{
    const size_t queued = bufferqueueGetCharge(&reader->pending);
    const size_t head   = reader->head == NULL ? 0 : sbufGetQueueCharge(reader->head);
    return queued > SIZE_MAX - head ? SIZE_MAX : queued + head;
}
