#include "buffer_stream.h"

#define i_TYPE queue, shift_buffer_t *
#include "stc/deq.h"
#define Q_CAP 25

struct buffer_stream_s
{
    buffer_pool_t *pool;
    queue q;
    size_t size;
};

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

bool bufferStreamRead(void *dest, size_t bytes, buffer_stream_t *self)
{
    if (self->size == 0 || self->size < bytes)
        return false;

    size_t wi = 0;
    while (true)
    {
        shift_buffer_t *b = queue_pull_front(&self->q);
        size_t blen = bufLen(b);

        if (blen > bytes)
        {
            memcpy(dest + wi, rawBuf(b), bytes);
            shiftr(b, bytes);
            queue_push_front(&self->q, b);
            self->size -= bytes;
            return true;
        }
        else if (blen == bytes)
        {
            memcpy(dest + wi, rawBuf(b), bytes);
            self->size -= bytes;
            reuseBuffer(self->pool, b);
            return true;
        }
        else
        {
            memcpy(dest + wi, rawBuf(b), blen);
            wi += blen;
            bytes -= blen;
            self->size -= blen;
            reuseBuffer(self->pool, b);
        }
    }
}

uint8_t bufferStreamReadByteAt(buffer_stream_t *self, size_t at)
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
            result = rawBuf(b)[at];
            return result;
        }
        else
        {
            at -= blen;
        }
    }
    return 0;
}

size_t bufferStreamLen(buffer_stream_t *self)
{
    return self->size;
}
