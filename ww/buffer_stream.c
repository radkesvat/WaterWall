#include "buffer_stream.h"

#undef max
#undef min
static inline size_t min(size_t x, size_t y) { return (((x) < (y)) ? (x) : (y)); }
static inline size_t max(size_t x, size_t y) { return (((x) > (y)) ? (x) : (y)); }

buffer_stream_t *newBufferStream(struct buffer_pool_s *pool)
{
    buffer_stream_t *bs = malloc(sizeof(buffer_stream_t));
    bs->q = queue_with_capacity(Q_CAP);
    bs->pool = pool;
    bs->size = 0;
    return bs;
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
    if (self->size == 0 || self->size < bytes)
        return NULL;
    self->size -= bytes;

    shift_buffer_t *result = queue_pull_front(&self->q);
    size_t available = bufLen(result);
    if (available > bytes)
    {
        shift_buffer_t *shadow = newShadowShiftBuffer(result);
        setLen(shadow, bytes);
        shiftr(result, bytes);
        queue_push_front(&self->q, result);
        return shadow;
    }
    else if (available == bytes)
    {

        return result;
    }
    else
    {
        size_t needed = bytes - available;
        size_t wi = available;
        setLen(result, bytes);
        uint8_t *dest = rawBufMut(result);

        while (true)
        {
            shift_buffer_t *b = queue_pull_front(&self->q);
            size_t blen = bufLen(b);

            if (blen > needed)
            {
                memcpy(dest + wi, rawBuf(b), needed);
                shiftr(b, needed);
                queue_push_front(&self->q, b);
                return result;
            }
            else if (blen == needed)
            {
                memcpy(dest + wi, rawBuf(b), needed);
                reuseBuffer(self->pool, b);
                return result;
            }
            else
            {
                memcpy(dest + wi, rawBuf(b), blen);
                wi += blen;
                needed -= blen;
                reuseBuffer(self->pool, b);
            }
        }
    }
}

uint8_t bufferStreamViewByteAt(buffer_stream_t *self, size_t at)
{
    if (self->size == 0 || self->size < at)
        return 0;

    uint8_t result = 0;
    c_foreach(i, queue, self->q)
    {

        shift_buffer_t *b = *i.ref;
        size_t blen = bufLen(b);

        if (at < blen)
        {
            result = ((uint8_t *)rawBuf(b))[at];
            return result;
        }
        else
        {
            at -= blen;
        }
    }
    return 0;
}
