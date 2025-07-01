#include "buffer_stream.h"
#include "buffer_pool.h"
#include "shiftbuffer.h"
#include "stc/common.h"

enum
{
    kQCap                = 16,
    kConcatMaxThreshould = 4096
};

/**
 * Creates a new buffer stream.
 * @param pool The buffer pool.
 * @return A pointer to the created buffer stream.
 */
buffer_stream_t *bufferstreamCreate(buffer_pool_t *pool)
{
    buffer_stream_t *bs = memoryAllocate(sizeof(buffer_stream_t));
    bs->q               = bs_doublequeue_t_with_capacity(kQCap);
    bs->pool            = pool;
    bs->size            = 0;
    return bs;
}

/**
 * Empties the buffer stream, returning all buffers to the pool.
 * @param self The buffer stream to empty.
 */
void bufferstreamEmpty(buffer_stream_t *self)
{
    c_foreach(i, bs_doublequeue_t, self->q)
    {
        bufferpoolReuseBuffer(self->pool, *i.ref);
    }
    bs_doublequeue_t_clear(&self->q);
    self->size = 0;
}

/**
 * Destroys the buffer stream and frees its resources.
 * @param self The buffer stream to destroy.
 */
void bufferstreamDestroy(buffer_stream_t *self)
{
    c_foreach(i, bs_doublequeue_t, self->q)
    {
        bufferpoolReuseBuffer(self->pool, *i.ref);
    }
    bs_doublequeue_t_drop(&self->q);
    memoryFree(self);
}

/**
 * Pushes a buffer into the buffer stream.
 * @param self The buffer stream.
 * @param buf The buffer to push.
 */
void bufferstreamPush(buffer_stream_t *self, sbuf_t *buf)
{

    BUFFER_WONT_BE_REUSED(buf);

    if (self->size > 0 && bs_doublequeue_t_size(&self->q) == 1)
    {
        sbuf_t  *last       = *bs_doublequeue_t_front(&self->q);
        uint32_t write_size = min(sbufGetRightCapacity(last), sbufGetLength(buf));

        if (write_size > 0)
        {
            self->size += write_size;
            sbufWrite(last, buf, write_size);
            if (sbufGetLength(buf) == write_size)
            {
                sbufDestroy(buf);
                return;
            }
            sbufShiftRight(buf, write_size);
        }
    }

    bs_doublequeue_t_push_back(&self->q, buf);
    self->size += sbufGetLength(buf);
}

/**
 * Reads an exact number of bytes from the buffer stream.
 * @param self The buffer stream.
 * @param bytes The number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadExact(buffer_stream_t *self, size_t bytes)
{
    assert(self->size >= bytes && bytes > 0);
    self->size -= bytes;

    sbuf_t *container = bs_doublequeue_t_pull_front(&self->q);

    while (true)
    {
        size_t available = sbufGetLength(container);
        if (available > bytes)
        {
            sbuf_t *slice = bufferpoolGetLargeBuffer(self->pool);
            slice         = sbufMoveTo(slice, container, (uint32_t) bytes);
            bs_doublequeue_t_push_front(&self->q, container);
            return slice;
        }
        if (available == bytes)
        {
            return container;
        }
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
    assert(self->size >= bytes && bytes > 0);
    self->size -= bytes;

    sbuf_t *container = bs_doublequeue_t_pull_front(&self->q);

    while (true)
    {
        size_t available = sbufGetLength(container);
        if (available >= bytes)
        {
            return container;
        }
        container = sbufAppendMerge(self->pool, container, bs_doublequeue_t_pull_front(&self->q));
    }
}

/**
 * Reads the ideal amount of data from the buffer stream.
 * @param self The buffer stream.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamIdealRead(buffer_stream_t *self)
{
    assert(self->size > 0);
    sbuf_t *container = bs_doublequeue_t_pull_front(&self->q);
    self->size -= sbufGetLength(container);
    return container;
}

/**
 * Views a byte at a specific position in the buffer stream.
 * @param self The buffer stream.
 * @param at The position to view the byte.
 * @return The byte at the specified position.
 */
uint8_t bufferstreamViewByteAt(buffer_stream_t *self, size_t at)
{
    assert(self->size > at && self->size != 0);

    uint8_t result = 0;
    c_foreach(i, bs_doublequeue_t, self->q)
    {
        sbuf_t *b    = *i.ref;
        size_t  blen = sbufGetLength(b);

        if (at < blen)
        {
            result = ((uint8_t *) sbufGetRawPtr(b))[at];
            return result;
        }

        at -= blen;
    }
    return 0;
}

/**
 * Views a sequence of bytes at a specific position in the buffer stream.
 * @param self The buffer stream.
 * @param at The position to start viewing the bytes.
 * @param buf The buffer to store the viewed bytes.
 * @param len The number of bytes to view.
 */
void bufferstreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len)
{
    size_t bufferstream_i = at;
    assert(self->size >= (bufferstream_i + len) && self->size != 0);
    uint32_t buf_i = 0;
    c_foreach(qi, bs_doublequeue_t, self->q)
    {

        sbuf_t *b    = *qi.ref;
        size_t  blen = sbufGetLength(b);

        if (len - buf_i <= blen - bufferstream_i)
        {
            memoryCopy(buf + buf_i, ((char *) sbufGetRawPtr(b)) + bufferstream_i, len - buf_i);
            return;
        }

        while (bufferstream_i < blen)
        {
            buf[buf_i++] = ((uint8_t *) sbufGetRawPtr(b))[bufferstream_i++];
            if (buf_i == len)
            {
                return;
            }
        }

        bufferstream_i -= blen;
    }
}
