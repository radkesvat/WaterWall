#pragma once
#include "wlibc.h"


#include "buffer_pool.h"
#include "shiftbuffer.h"

/*

    This implements a simple container that holds buffers, some opmizations are also applied.

    you can for example check byte index 1 or 5 of the buffers without concating them, then
    you'll be able to read only when your protocol is satisfied, the size you want


*/

#define i_type queue
#define i_key sbuf_t *
#include "stc/deque.h"

struct buffer_stream_s
{
    buffer_pool_t *pool;
    queue          q;
    size_t         size;

};

typedef struct buffer_stream_s buffer_stream_t;

/**
 * Creates a new buffer stream.
 * @param pool The buffer pool.
 * @return A pointer to the created buffer stream.
 */
buffer_stream_t *bufferstreamCreate(buffer_pool_t *pool);

/**
 * Empties the buffer stream, returning all buffers to the pool.
 * @param self The buffer stream to empty.
 */
void bufferstreamEmpty(buffer_stream_t *self);

/**
 * Destroys the buffer stream and frees its resources.
 * @param self The buffer stream to destroy.
 */
void bufferstreamDestroy(buffer_stream_t *self);

/**
 * Pushes a buffer into the buffer stream.
 * @param self The buffer stream.
 * @param buf The buffer to push.
 */
void bufferstreamPush(buffer_stream_t *self, sbuf_t *buf);

/**
 * Reads an exact number of bytes from the buffer stream.
 * @param self The buffer stream.
 * @param bytes The number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadExact(buffer_stream_t *self, size_t bytes);

/**
 * Reads at least a specified number of bytes from the buffer stream.
 * @param self The buffer stream.
 * @param bytes The minimum number of bytes to read.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamReadAtLeast(buffer_stream_t *self, size_t bytes);

/**
 * Reads the ideal amount of data from the buffer stream.
 * @param self The buffer stream.
 * @return A pointer to the buffer containing the read data.
 */
sbuf_t *bufferstreamIdealRead(buffer_stream_t *self);

/**
 * Views a byte at a specific position in the buffer stream.
 * @param self The buffer stream.
 * @param at The position to view the byte.
 * @return The byte at the specified position.
 */
uint8_t bufferstreamViewByteAt(buffer_stream_t *self, size_t at);

/**
 * Views a sequence of bytes at a specific position in the buffer stream.
 * @param self The buffer stream.
 * @param at The position to start viewing the bytes.
 * @param buf The buffer to store the viewed bytes.
 * @param len The number of bytes to view.
 */
void bufferstreamViewBytesAt(buffer_stream_t *self, size_t at, uint8_t *buf, size_t len);

/**
 * Gets the length of the buffer stream.
 * @param self The buffer stream.
 * @return The length of the buffer stream.
 */
static inline size_t bufferstreamLen(buffer_stream_t *self)
{
    return self->size;
}

/**
 * Reads the full length of the buffer stream.
 * @param self The buffer stream.
 * @return A pointer to the buffer containing the read data.
 */
static inline sbuf_t *bufferstreamFullRead(buffer_stream_t *self)
{
    return bufferstreamReadExact(self, bufferstreamLen(self));
}

