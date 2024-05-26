#include "buffer_stream.h"
#include "buffer_pool.h"
#include "shiftbuffer.h"
#include "stc/common.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern size_t          bufferStreamLen(buffer_stream_t *self);
extern shift_buffer_t *bufferStreamFullRead(buffer_stream_t *self);

enum
{
    kQCap = 32
};

buffer_stream_t *newBufferStream(struct buffer_pool_s *pool)
{
    buffer_stream_t *bs = malloc(sizeof(buffer_stream_t));
    bs->q               = queue_with_capacity(kQCap);
    bs->pool            = pool;
    bs->size            = 0;
    return bs;
}

void empytBufferStream(buffer_stream_t *self)
{
    c_foreach(i, queue, self->q)
    {
        reuseBuffer(self->pool, *i.ref);
    }
    queue_clear(&self->q);
    self->size = 0;
}

void destroyBufferStream(buffer_stream_t *self)
{
    c_foreach(i, queue, self->q)
    {
        reuseBuffer(self->pool, *i.ref);
    }
    queue_drop(&self->q);
    free(self);
}

void bufferStreamPush(buffer_stream_t *self, shift_buffer_t *buf)
{
    queue_push_back(&self->q, buf);
    self->size += bufLen(buf);
}

shift_buffer_t *bufferStreamRead(buffer_stream_t *self, size_t bytes)
{
    assert(self->size >= bytes && bytes > 0);
    self->size -= bytes;

    shift_buffer_t *container = queue_pull_front(&self->q);

    while (true)
    {
        size_t available = bufLen(container);
        if (available > bytes)
        {
            shift_buffer_t *slice = popBuffer(self->pool);
            sliceBufferTo(slice, container, bytes);
            queue_push_front(&self->q, container);
            return slice;
        }
        if (available == bytes)
        {
            return container;
        }
        container = appendBufferMerge(self->pool, container, queue_pull_front(&self->q));
    }

    // shift_buffer_t *b = queue_pull_front(&self->q);

    // size_t needed = bytes - available;
    // size_t wi     = available;
    // setLen(result, bytes);
    // uint8_t *dest = rawBufMut(result);

    // while (true)
    // {
    //     shift_buffer_t *b    = queue_pull_front(&self->q);
    //     size_t          blen = bufLen(b);

    //     if (blen > needed)
    //     {
    //         memcpy(dest + wi, rawBuf(b), needed);
    //         shiftr(b, needed);
    //         queue_push_front(&self->q, b);
    //         return result;
    //     }
    //     if (blen == needed)
    //     {
    //         memcpy(dest + wi, rawBuf(b), needed);
    //         reuseBuffer(self->pool, b);
    //         return result;
    //     }

    //     memcpy(dest + wi, rawBuf(b), blen);
    //     wi += blen;
    //     needed -= blen;
    //     reuseBuffer(self->pool, b);
    // }
}
shift_buffer_t *bufferStreamIdealRead(buffer_stream_t *self)
{
    assert(self->size > 0);
    shift_buffer_t *container = queue_pull_front(&self->q);
    self->size -= bufLen(container);
    return container;
}

uint8_t bufferStreamViewByteAt(buffer_stream_t *self, size_t at)
{
    assert(self->size > at && self->size != 0);

    uint8_t result = 0;
    c_foreach(i, queue, self->q)
    {

        shift_buffer_t *b    = *i.ref;
        size_t          blen = bufLen(b);

        if (at < blen)
        {
            result = ((uint8_t *) rawBuf(b))[at];
            return result;
        }

        at -= blen;
    }
    return 0;
}

// todo (test) this could be implemented incorrectly, you didn't write unit tests -> you choosed to suffer
void bufferStreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len)
{
    size_t bufferstream_i = at;
    assert(self->size >= (bufferstream_i + len) && self->size != 0);
    unsigned int buf_i = 0;
    c_foreach(qi, queue, self->q)
    {

        shift_buffer_t *b    = *qi.ref;
        size_t          blen = bufLen(b);
        if (len - buf_i <= blen - bufferstream_i)
        {
            memcpy(buf + buf_i, ((char *) rawBuf(b)) + bufferstream_i, len - buf_i);
            return;
        }
        while (bufferstream_i < blen)
        {

            buf[buf_i++] = ((uint8_t *) rawBuf(b))[bufferstream_i++];
            if (buf_i == len)
            {
                return;
            }
        }

        bufferstream_i -= blen;
    }
}
