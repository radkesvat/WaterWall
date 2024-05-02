#pragma once
#include "buffer_pool.h"
#include "shiftbuffer.h"
#include <stddef.h>
#include <stdint.h>

/*
    buffers look like packets , you want a stream? you want to read the length you want?
    then use buffer stream! put every buffer into this mix box and now you have a flow of bytes
    which you can read but not consume, save and keep appending data to it untill it statisfy your protocol

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

inline size_t bufferStreamLen(buffer_stream_t *self)
{
    return self->size;
}
