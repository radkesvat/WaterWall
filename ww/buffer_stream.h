#pragma once
#include "buffer_pool.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include <stddef.h>
#include <stdint.h>

/*

    This implements a simple container that holds buffers, some opmizations are also applied.

    you can for example check byte index 1 or 5 of the buffers without concating them, then
    you'll be able to read only when your protocol is satisfied, the size you want


*/

#define i_TYPE queue, shift_buffer_t * // NOLINT
#include "stc/deq.h"

struct buffer_stream_s
{
    buffer_pool_t *pool;
    queue          q;
    size_t         size;
};

typedef struct buffer_stream_s buffer_stream_t;

buffer_stream_t *newBufferStream(buffer_pool_t *pool);
void             empytBufferStream(buffer_stream_t *self);
void             destroyBufferStream(buffer_stream_t *self);
void             bufferStreamPush(buffer_stream_t *self, shift_buffer_t *buf);
shift_buffer_t  *bufferStreamRead(buffer_stream_t *self, size_t bytes);
shift_buffer_t  *bufferStreamIdealRead(buffer_stream_t *self);
uint8_t          bufferStreamViewByteAt(buffer_stream_t *self, size_t at);
void             bufferStreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len);

static inline size_t bufferStreamLen(buffer_stream_t *self)
{
    return self->size;
}

static inline shift_buffer_t *bufferStreamFullRead(buffer_stream_t *self)
{
    return bufferStreamRead(self, bufferStreamLen(self));
}

static inline void bufferStreamPushContextPayload(buffer_stream_t *self,context_t *c)
{
    assert(c->payload);
    bufferStreamPush(self,c->payload);
    CONTEXT_PAYLOAD_DROP(c);
}
