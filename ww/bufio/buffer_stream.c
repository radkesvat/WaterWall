/*
 * Implements queued stream-style reads over pooled sbuf_t buffers.
 */

#include "buffer_stream.h"
#include "buffer_pool.h"
#include "shiftbuffer.h"
#include "stc/common.h"

enum
{
    kBufferStreamQCap                      = 16,
    kBufferStreamCoalescingMaxIncomingSize = 4096
};

static inline void bufferstreamCheckSbufByteCount(size_t bytes, const char *operation)
{
    if (UNLIKELY(bytes > UINT32_MAX))
    {
        printError("BufferStream: %s exceeds sbuf_t 32-bit limit (%zu bytes)", operation, bytes);
        abortProgramNow(1);
    }
}

static uint32_t bufferstreamValidatePush(buffer_stream_t *self, sbuf_t *buf)
{
    assert(self != NULL && buf != NULL);

    const uint32_t buf_len = sbufGetLength(buf);
    bufferstreamCheckSbufByteCount(buf_len, "push");

    if (UNLIKELY(self->size > (size_t) UINT32_MAX - buf_len))
    {
        printError("BufferStream: buffered data exceeds sbuf_t 32-bit limit");
        abortProgramNow(1);
    }

    return buf_len;
}

static void bufferstreamEnqueueValidated(buffer_stream_t *self, sbuf_t *buf, uint32_t buf_len)
{
    bs_doublequeue_t_push_back(&self->q, buf);
    self->size += buf_len;
}

static sbuf_t *bufferstreamAllocExactReadBuffer(buffer_stream_t *self, uint32_t bytes)
{
    const uint16_t use_left_padding = self->use_left_padding;
    const uint32_t required_payload = bytes > use_left_padding ? bytes - use_left_padding : 0;
    sbuf_t        *slice;

    if (required_payload <= bufferpoolGetSmallBufferSize(self->pool) &&
        use_left_padding <= bufferpoolGetSmallBufferPadding(self->pool))
    {
        slice = bufferpoolGetSmallBuffer(self->pool);
    }
    else
    {
        slice = bufferpoolGetLargeBuffer(self->pool);
    }

    assert(sbufGetLeftCapacity(slice) >= use_left_padding);
    if (use_left_padding > 0)
    {
        sbufShiftLeft(slice, use_left_padding);
        sbufSetLength(slice, 0);
    }

    return sbufReserveSpace(slice, bytes);
}

buffer_stream_t bufferstreamCreate(buffer_pool_t *pool, uint16_t use_left_padding)
{
    assert(pool != NULL);

    buffer_stream_t bs = {.use_left_padding = use_left_padding,
                          .q                = bs_doublequeue_t_with_capacity(kBufferStreamQCap),
                          .pool             = pool,
                          .size             = 0};

    return bs;
}

void bufferstreamEmpty(buffer_stream_t *self)
{
    assert(self != NULL);

    c_foreach(i, bs_doublequeue_t, self->q)
    {
        bufferpoolReuseBuffer(self->pool, *i.ref);
    }
    bs_doublequeue_t_clear(&self->q);
    self->size = 0;
}

void bufferstreamDestroy(buffer_stream_t *self)
{
    assert(self != NULL);

    c_foreach(i, bs_doublequeue_t, self->q)
    {
        bufferpoolReuseBuffer(self->pool, *i.ref);
    }
    bs_doublequeue_t_drop(&self->q);
}

void bufferstreamPush(buffer_stream_t *self, sbuf_t *buf)
{
    const uint32_t buf_len = bufferstreamValidatePush(self, buf);
    bufferstreamEnqueueValidated(self, buf, buf_len);
}

void bufferstreamPushCoalescing(buffer_stream_t *self, sbuf_t *buf)
{
    const uint32_t incoming_len = bufferstreamValidatePush(self, buf);

    if (! bs_doublequeue_t_is_empty(&self->q) && incoming_len > 0 &&
        incoming_len <= kBufferStreamCoalescingMaxIncomingSize)
    {
        sbuf_t *tail = *bs_doublequeue_t_back(&self->q);

        if (tail != buf && ! tail->is_temporary && ! buf->is_temporary && sbufGetLifetime(tail) == NULL &&
            sbufGetLifetime(buf) == NULL)
        {
            const uint32_t tail_len              = sbufGetLength(tail);
            const uint32_t tail_maximum_writable = sbufGetMaximumWriteableSize(tail);
            assert(tail_len <= tail_maximum_writable);
            const uint32_t tail_spare = tail_maximum_writable - tail_len;

            if (incoming_len <= tail_spare)
            {
                memoryCopy(sbufGetMutablePtr(tail) + tail_len, sbufGetRawPtr(buf), incoming_len);
                sbufSetLength(tail, tail_len + incoming_len);
                self->size += incoming_len;
                bufferpoolReuseBuffer(self->pool, buf);
                return;
            }
        }
    }

    bufferstreamEnqueueValidated(self, buf, incoming_len);
}

sbuf_t *bufferstreamReadExact(buffer_stream_t *self, size_t bytes)
{
    assert(self && self->size >= bytes && bytes > 0);
    assert(bs_doublequeue_t_size(&self->q) > 0); // Ensure queue is not empty
    bufferstreamCheckSbufByteCount(bytes, "exact read");

    self->size -= bytes;

    sbuf_t *container = bs_doublequeue_t_pull_front(&self->q);

    while (true)
    {
        size_t available = sbufGetLength(container);
        if (available > bytes)
        {
            sbuf_t *slice = bufferstreamAllocExactReadBuffer(self, (uint32_t) bytes);

            slice = sbufMoveTo(slice, container, (uint32_t) bytes);
            bs_doublequeue_t_push_front(&self->q, container);
            return slice;
        }
        if (available == bytes)
        {
            return container;
        }

        // Assert queue is not empty - this should never happen if size accounting is correct
        assert(bs_doublequeue_t_size(&self->q) > 0 && "Buffer stream size inconsistency detected");

        container = sbufAppendMerge(self->pool, container, bs_doublequeue_t_pull_front(&self->q));
    }
}

sbuf_t *bufferstreamReadAtLeast(buffer_stream_t *self, size_t bytes)
{
    assert(self && self->size >= bytes && bytes > 0);
    assert(bs_doublequeue_t_size(&self->q) > 0); // Ensure queue is not empty
    bufferstreamCheckSbufByteCount(bytes, "at-least read");

    sbuf_t *container = bs_doublequeue_t_pull_front(&self->q);
    size_t  consumed  = sbufGetLength(container);

    while (true)
    {
        size_t available = sbufGetLength(container);
        if (available >= bytes)
        {
            self->size -= consumed;
            return container;
        }

        // Assert queue is not empty - this should never happen if size accounting is correct
        assert(bs_doublequeue_t_size(&self->q) > 0 && "Buffer stream size inconsistency detected");

        sbuf_t *next = bs_doublequeue_t_pull_front(&self->q);
        consumed += sbufGetLength(next);
        container = sbufAppendMerge(self->pool, container, next);
    }
}

sbuf_t *bufferstreamIdealRead(buffer_stream_t *self)
{
    assert(self && self->size > 0);
    assert(bs_doublequeue_t_size(&self->q) > 0); // Ensure queue is not empty

    sbuf_t *container = bs_doublequeue_t_pull_front(&self->q);
    self->size -= sbufGetLength(container);
    return container;
}

uint8_t bufferstreamViewByteAt(buffer_stream_t *self, size_t at)
{
    if (UNLIKELY(self == NULL))
    {
        printError("BufferStream: cannot view a byte from a NULL stream");
        abortProgramNow(1);
    }
    if (UNLIKELY(at >= self->size))
    {
        printError("BufferStream: byte index %zu is out of range for %zu buffered bytes", at, self->size);
        abortProgramNow(1);
    }

    size_t offset = at;
    c_foreach(i, bs_doublequeue_t, self->q)
    {
        sbuf_t *b    = *i.ref;
        size_t  blen = sbufGetLength(b);

        if (offset < blen)
        {
            return ((uint8_t *) sbufGetRawPtr(b))[offset];
        }

        offset -= blen;
    }

    printError("BufferStream: size accounting is inconsistent while viewing byte %zu of %zu", at, self->size);
    abortProgramNow(1);
}

void bufferstreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len)
{
    // Use subtraction-based bounds checks to avoid overflow in (at + len).
    const bool valid =
        self != NULL && buf != NULL && len > 0 && self->size != 0 && at <= self->size && len <= (self->size - at);
    assert(valid);
    if (UNLIKELY(! valid))
    {
        printError("BufferStream: invalid byte-view range (offset=%zu, length=%zu)", at, len);
        abortProgramNow(1);
    }

    size_t remaining_offset = at;
    size_t buf_i            = 0;

    c_foreach(qi, bs_doublequeue_t, self->q)
    {
        sbuf_t *b    = *qi.ref;
        size_t  blen = sbufGetLength(b);

        // Skip buffers that are entirely before our starting position
        if (remaining_offset >= blen)
        {
            remaining_offset -= blen;
            continue;
        }

        // Copy what we can from this buffer
        size_t copy_start = remaining_offset;
        size_t copy_len   = min(len - buf_i, blen - copy_start);

        memoryCopy(buf + buf_i, ((char *) sbufGetRawPtr(b)) + copy_start, copy_len);
        buf_i += copy_len;
        remaining_offset = 0; // For subsequent buffers, start from beginning

        if (buf_i == len)
        {
            return;
        }
    }

    printError("BufferStream: size accounting is inconsistent while viewing %zu byte(s) at offset %zu", len, at);
    abortProgramNow(1);
}
