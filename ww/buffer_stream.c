#include "buffer_stream.h"
#include "utils/mathutils.h"

buffer_stream_t *newBufferStream(struct buffer_pool_s *pool)
{
    buffer_stream_t *bs = malloc(sizeof(buffer_stream_t));
    bs->q               = queue_with_capacity(Q_CAP);
    bs->pool            = pool;
    bs->size            = 0;
    return bs;
}

void empytBufferStream(buffer_stream_t *self)
{
    c_foreach(i, queue, self->q) { reuseBuffer(self->pool, *i.ref); }
    queue_clear(&self->q);
}

void destroyBufferStream(buffer_stream_t *self)
{
    c_foreach(i, queue, self->q) { reuseBuffer(self->pool, *i.ref); }
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
    assert(self->size >= bytes);
    if (self->size == 0)
    {
        return NULL;
    }
    self->size -= bytes;

    shift_buffer_t *result = queue_pull_front(&self->q);

    while (true)
    {
        size_t available = bufLen(result);
        if (available > bytes)
        {
            shift_buffer_t *shadow = newShallowShiftBuffer(result);
            setLen(shadow, bytes);
            shiftr(result, bytes);
            // choose the smallest copy 
            // if(available >  bytes * 2){
            //     unShallow(shadow);
            // }else{
            //     unShallow(result);
            // }
            queue_push_front(&self->q, result);
            return shadow;
        }
        if (available == bytes)
        {
            return result;
        }
        result = appendBufferMerge(self->pool,result, queue_pull_front(&self->q));
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

// todo (test) this can be implemented incorrectly, you didn't write unit tests -> you choosed to suffer
void bufferStreamViewBytesAt(buffer_stream_t *self, uint8_t *buf, size_t at, size_t len)
{
    assert(self->size >= (at + len) && self->size != 0);
    unsigned int i = 0;
    c_foreach(qi, queue, self->q)
    {

        shift_buffer_t *b    = *qi.ref;
        size_t          blen = bufLen(b);

        while (at < blen)
        {
            if (len - i <= blen - at)
            {
                memcpy(buf + i, rawBuf(b) + at, len - i);
                return;
            }
            buf[i++] = ((uint8_t *) rawBuf(b))[at++];
            if (i == len)
            {
                return;
            }
        }

        at -= blen;
    }
}
