#include "buffer_stream.h"
#include "buffer_pool.h"
#include "shiftbuffer.h"
#include "stc/common.h"

enum
{
    kQCap                = 16,
    kConcatMaxThreshould = 4096
};

buffer_stream_t bufferstreamCreate(buffer_pool_t *pool, uint16_t use_left_padding)
{
    assert(pool != NULL);

    buffer_stream_t bs = {
        .use_left_padding = use_left_padding,
        .q = bs_doublequeue_t_with_capacity(kQCap),
        .pool = pool,
        .size = 0
    };

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
    assert(self != NULL && buf != NULL);

    // BUFFER_WONT_BE_REUSED(buf);

    // if (self->size > 0 && bs_doublequeue_t_size(&self->q) == 1)
    // {
    //     sbuf_t  *last       = *bs_doublequeue_t_front(&self->q);
    //     uint32_t write_size = min(sbufGetRightCapacity(last), sbufGetLength(buf));

    //     if (write_size > 0)
    //     {
    //         // Check for potential overflow
    //         assert(self->size <= SIZE_MAX - write_size);

    //         sbufWriteLarge(last, buf, write_size);
    //         sbufSetLength(last, sbufGetLength(last) + write_size);
    //         self->size += write_size;

    //         sbufShiftRight(buf, write_size);

    //         if (sbufGetLength(buf) == 0)
    //         {
    //             sbufDestroy(buf);
    //             return;
    //         }
    //     }
    // }

    size_t buf_len = sbufGetLength(buf);
    // Check for potential overflow
    assert(self->size <= SIZE_MAX - buf_len);

    bs_doublequeue_t_push_back(&self->q, buf);
    self->size += buf_len;
}

sbuf_t *bufferstreamReadExact(buffer_stream_t *self, size_t bytes)
{
    assert(self && self->size >= bytes && bytes > 0);
    assert(bs_doublequeue_t_size(&self->q) > 0); // Ensure queue is not empty

    self->size -= bytes;

    sbuf_t *container = bs_doublequeue_t_pull_front(&self->q);

    while (true)
    {
        size_t available = sbufGetLength(container);
        if (available > bytes)
        {
            sbuf_t *slice = bufferpoolGetLargeBuffer(self->pool);

            if (self->use_left_padding > 0)
            {
                sbufShiftLeft(slice, self->use_left_padding);
                sbufSetLength(slice, 0);
            }
            slice = sbufReserveSpace(slice, (uint32_t) bytes);

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

/**
 * Reads at least a specified number of bytes from the buffer stream.
 * @param self The buffer stream.
 * @param bytes The minimum number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadAtLeast(buffer_stream_t *self, size_t bytes)
{
    assert(self && self->size >= bytes && bytes > 0);
    assert(bs_doublequeue_t_size(&self->q) > 0); // Ensure queue is not empty

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
    assert(self && self->size > at && self->size != 0);

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
    return 0;
}

void bufferstreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len)
{

    assert(self && buf && len > 0 && self->size >= (at + len) && self->size != 0);

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
}
