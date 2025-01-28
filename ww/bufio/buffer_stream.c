#include "buffer_stream.h"
#include "buffer_pool.h"
#include "shiftbuffer.h"
#include "stc/common.h"

enum
{
    kQCap                = 16,
    kConcatMaxThreshould = 4096
};

buffer_stream_t *newBufferStream(buffer_pool_t *pool)
{
    buffer_stream_t *bs = memoryAllocate(sizeof(buffer_stream_t));
    bs->q               = queue_with_capacity(kQCap);
    bs->pool            = pool;
    bs->size            = 0;
    return bs;
}

void emptyBufferStream(buffer_stream_t *self)
{
    c_foreach(i, queue, self->q)
    {
        bufferpoolResuesBuffer(self->pool, *i.ref);
    }
    queue_clear(&self->q);
    self->size = 0;
}

void destroyBufferStream(buffer_stream_t *self)
{
    c_foreach(i, queue, self->q)
    {
        bufferpoolResuesBuffer(self->pool, *i.ref);
    }
    queue_drop(&self->q);
    memoryFree(self);
}

void bufferStreamPush(buffer_stream_t *self, sbuf_t *buf)
{

    BUFFER_WONT_BE_REUSED(buf);

    if (self->size > 0 && queue_size(&self->q) == 1)
    {
        sbuf_t  *last       = *queue_front(&self->q);
        uint32_t write_size = min(sbufGetRightCapacityNoPadding(last), sbufGetBufLength(buf));

        if (write_size > 0)
        {
            self->size += write_size;
            sbufWrite(last, buf, write_size);
            if (sbufGetBufLength(buf) == write_size)
            {
                sbufDestroy(buf);
                return;
            }
            sbufShiftRight(buf, write_size);
        }
    }

    queue_push_back(&self->q, buf);
    self->size += sbufGetBufLength(buf);
}

sbuf_t *bufferStreamReadExact(buffer_stream_t *self, size_t bytes)
{
    assert(self->size >= bytes && bytes > 0);
    self->size -= bytes;

    sbuf_t *container = queue_pull_front(&self->q);

    while (true)
    {
        size_t available = sbufGetBufLength(container);
        if (available > bytes)
        {
            sbuf_t *slice = bufferpoolGetLargeBuffer(self->pool);
            slice         = sbufMoveTo(slice, container, bytes);
            queue_push_front(&self->q, container);
            return slice;
        }
        if (available == bytes)
        {
            return container;
        }
        container = sbufAppendMergeNoPadding(self->pool, container, queue_pull_front(&self->q));
    }
}

sbuf_t *bufferStreamReadAtLeast(buffer_stream_t *self, size_t bytes)
{
    assert(self->size >= bytes && bytes > 0);
    self->size -= bytes;

    sbuf_t *container = queue_pull_front(&self->q);

    while (true)
    {
        size_t available = sbufGetBufLength(container);
        if (available >= bytes)
        {
            return container;
        }
        container = sbufAppendMerge(self->pool, container, queue_pull_front(&self->q));
    }
}



sbuf_t *bufferStreamIdealRead(buffer_stream_t *self)
{
    assert(self->size > 0);
    sbuf_t *container = queue_pull_front(&self->q);
    self->size -= sbufGetBufLength(container);
    return container;
}

uint8_t bufferStreamViewByteAt(buffer_stream_t *self, size_t at)
{
    assert(self->size > at && self->size != 0);

    uint8_t result = 0;
    c_foreach(i, queue, self->q)
    {
        sbuf_t *b    = *i.ref;
        size_t  blen = sbufGetBufLength(b);

        if (at < blen)
        {
            result = ((uint8_t *) sbufGetRawPtr(b))[at];
            return result;
        }

        at -= blen;
    }
    return 0;
}

void bufferStreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len)
{
    size_t bufferstream_i = at;
    assert(self->size >= (bufferstream_i + len) && self->size != 0);
    unsigned int buf_i = 0;
    c_foreach(qi, queue, self->q)
    {

        sbuf_t *b    = *qi.ref;
        size_t  blen = sbufGetBufLength(b);

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
