#pragma once

#include "buffer_pool.h"

#define i_TYPE queue, shift_buffer_t *
#include "stc/deq.h"
#define Q_CAP 25

struct buffer_stream_s
{
    buffer_pool_t *pool;
    queue q;
    size_t size;
};

typedef struct buffer_stream_s buffer_stream_t;

buffer_stream_t *newBufferStream(buffer_pool_t *pool);
void destroyBufferStream(buffer_stream_t *self);

void bufferStreamPush(buffer_stream_t *self, shift_buffer_t *buf);

shift_buffer_t *bufferStreamRead(buffer_stream_t *self, size_t bytes);

uint8_t bufferStreamViewByteAt(buffer_stream_t *self, size_t at);

static inline size_t bufferStreamLen(buffer_stream_t *self) { return self->size; }
