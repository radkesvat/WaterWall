#pragma once

#include "buffer_pool.h"

typedef struct buffer_stream_s buffer_stream_t;

buffer_stream_t *newBufferStream(buffer_pool_t *pool);
void destroyBufferStream(buffer_stream_t *self);

void bufferStreamPush(buffer_stream_t *self, shift_buffer_t *buf);

shift_buffer_t *bufferStreamRead(size_t bytes, buffer_stream_t *self);

uint8_t bufferStreamReadByteAt(buffer_stream_t *self, size_t at);

size_t bufferStreamLen(buffer_stream_t *self);
